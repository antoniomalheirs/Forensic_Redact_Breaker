// ========================================================================
// RedactBreaker v1.0 - PDF Redaction Forensic Analyzer (C++ Edition)
// Architecture: Single-file C++ (Brute Force Methods Style)
// Dependencies: Windows SDK (GDI+), picosha2.h (header-only)
// Compilation: cl /EHsc /O2 /std:c++17 RedactBreaker.cpp /link gdiplus.lib
// ========================================================================
// [!] FERRAMENTA EDUCACIONAL PARA ANALISE FORENSE [!]
// [!] O USO NAO AUTORIZADO EM DADOS DE TERCEIROS E PROIBIDO [!]
// ========================================================================

// Windows + GDI+ headers (must come first, before C++ standard headers on MSVC)
// GDI+ needs full GDI — do NOT use WIN32_LEAN_AND_MEAN
// GDI+ headers use unqualified min/max, so we define NOMINMAX then provide them
#define NOMINMAX
#include <windows.h>
// Provide min/max for GDI+ headers
#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif
#include <gdiplus.h>
#include <shlwapi.h>
// Now undefine min/max macros so our C++ code uses std::min/std::max
#undef min
#undef max

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "picosha2.h"

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "shlwapi.lib")

namespace fs = std::filesystem;

// ========================================================================
// STRUCTS
// ========================================================================
struct Rect {
  double x0 = 0, y0 = 0, x1 = 0, y1 = 0;
  double area() const {
    return std::max(0.0, x1 - x0) * std::max(0.0, y1 - y0);
  }
  double width() const { return x1 - x0; }
  double height() const { return y1 - y0; }
  bool isEmpty() const { return width() <= 0 || height() <= 0; }
  Rect intersect(const Rect &o) const {
    Rect r;
    r.x0 = std::max(x0, o.x0);
    r.y0 = std::max(y0, o.y0);
    r.x1 = std::min(x1, o.x1);
    r.y1 = std::min(y1, o.y1);
    return r;
  }
};

struct TextSpan {
  std::string text;
  Rect bbox;
  int colorRGB = 0;
  double fontSize = 12;
  std::string fontName;
};

struct VectorRect {
  Rect bbox;
  double r = 0, g = 0, b = 0;
  bool isFilled = false;
};

struct ImageInfo {
  int width = 0, height = 0;
  int bitsPerComponent = 8;
  std::string colorSpace;
  std::string filter;
  std::vector<unsigned char> data;
  Rect bbox;
  int page = 0;
};

struct RedactionCandidate {
  std::string id;
  Rect bbox;
  double colorR = 0, colorG = 0, colorB = 0;
  std::string confidence; // HIGH, MEDIUM, LOW
  std::string type;       // VECTOR_OVERLAY, RASTER_DETECTED
  int page = 0;
};

struct Breach {
  std::string type;
  std::string severity;
  std::string status;
  std::string candidateId;
  int page = 0;
  Rect bbox;
  std::string recoveredText;
  std::string justification;
};

struct EvidenceRecord {
  std::string evidenceId;
  std::string filePath;
  std::string fileName;
  size_t fileSize = 0;
  std::string sha256;
  std::string creationTime;
  std::string accessTime;
  std::string mimeType;
  std::string integrityStatus;
};

struct MetadataResult {
  std::map<std::string, std::string> standard;
  bool hasXMP = false;
  std::vector<std::string> suspiciousTags;
};

// ========================================================================
// MINIMAL INFLATE (RFC 1951 DEFLATE) for PDF FlateDecode
// ========================================================================
namespace tinflate {

static const unsigned short lengthBase[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const unsigned short lengthExtra[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
                                               1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
                                               4, 4, 4, 4, 5, 5, 5, 5, 0};
static const unsigned short distBase[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const unsigned short distExtra[30] = {
    0, 0, 0, 0, 1, 1, 2, 2,  3,  3,  4,  4,  5,  5,  6,
    6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
static const unsigned char clOrder[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                          11, 4,  12, 3, 13, 2, 14, 1, 15};

struct BitReader {
  const unsigned char *data;
  size_t size;
  size_t pos;
  unsigned int bitbuf;
  int bitcount;

  BitReader(const unsigned char *d, size_t s)
      : data(d), size(s), pos(0), bitbuf(0), bitcount(0) {}

  unsigned int readBits(int n) {
    while (bitcount < n) {
      if (pos >= size)
        return 0;
      bitbuf |= (unsigned int)data[pos++] << bitcount;
      bitcount += 8;
    }
    unsigned int val = bitbuf & ((1u << n) - 1);
    bitbuf >>= n;
    bitcount -= n;
    return val;
  }
};

struct HuffTree {
  unsigned short counts[16] = {};
  unsigned short symbols[288] = {};
  int maxSym = 0;
};

static void buildTree(HuffTree &tree, const unsigned char *lengths, int num) {
  memset(tree.counts, 0, sizeof(tree.counts));
  tree.maxSym = num;
  for (int i = 0; i < num; i++)
    tree.counts[lengths[i]]++;
  tree.counts[0] = 0;
  unsigned short offsets[16];
  offsets[0] = 0;
  for (int i = 1; i < 16; i++)
    offsets[i] = offsets[i - 1] + tree.counts[i - 1];
  for (int i = 0; i < num; i++) {
    if (lengths[i])
      tree.symbols[offsets[lengths[i]]++] = (unsigned short)i;
  }
}

static int decode(BitReader &br, const HuffTree &tree) {
  int code = 0, first = 0, index = 0;
  for (int len = 1; len < 16; len++) {
    code |= (int)br.readBits(1);
    int count = tree.counts[len];
    if (code < first + count)
      return tree.symbols[index + (code - first)];
    index += count;
    first = (first + count) << 1;
    code <<= 1;
  }
  return -1;
}

static void buildFixedTrees(HuffTree &lt, HuffTree &dt) {
  unsigned char lengths[288];
  for (int i = 0; i < 144; i++)
    lengths[i] = 8;
  for (int i = 144; i < 256; i++)
    lengths[i] = 9;
  for (int i = 256; i < 280; i++)
    lengths[i] = 7;
  for (int i = 280; i < 288; i++)
    lengths[i] = 8;
  buildTree(lt, lengths, 288);
  for (int i = 0; i < 30; i++)
    lengths[i] = 5;
  buildTree(dt, lengths, 30);
}

static bool decodeDynTrees(BitReader &br, HuffTree &lt, HuffTree &dt) {
  int hlit = (int)br.readBits(5) + 257;
  int hdist = (int)br.readBits(5) + 1;
  int hclen = (int)br.readBits(4) + 4;
  unsigned char clLengths[19] = {};
  for (int i = 0; i < hclen; i++)
    clLengths[clOrder[i]] = (unsigned char)br.readBits(3);
  HuffTree clTree;
  buildTree(clTree, clLengths, 19);
  unsigned char lengths[288 + 32] = {};
  int total = hlit + hdist;
  for (int i = 0; i < total;) {
    int sym = decode(br, clTree);
    if (sym < 0)
      return false;
    if (sym < 16) {
      lengths[i++] = (unsigned char)sym;
    } else if (sym == 16) {
      int rep = (int)br.readBits(2) + 3;
      unsigned char prev = i > 0 ? lengths[i - 1] : 0;
      for (int j = 0; j < rep && i < total; j++)
        lengths[i++] = prev;
    } else if (sym == 17) {
      int rep = (int)br.readBits(3) + 3;
      for (int j = 0; j < rep && i < total; j++)
        lengths[i++] = 0;
    } else {
      int rep = (int)br.readBits(7) + 11;
      for (int j = 0; j < rep && i < total; j++)
        lengths[i++] = 0;
    }
  }
  buildTree(lt, lengths, hlit);
  buildTree(dt, lengths + hlit, hdist);
  return true;
}

static bool inflateBlock(BitReader &br, const HuffTree &lt, const HuffTree &dt,
                         std::vector<unsigned char> &out) {
  while (true) {
    int sym = decode(br, lt);
    if (sym < 0)
      return false;
    if (sym == 256)
      return true;
    if (sym < 256) {
      out.push_back((unsigned char)sym);
    } else {
      sym -= 257;
      if (sym >= 29)
        return false;
      int length = lengthBase[sym] + (int)br.readBits(lengthExtra[sym]);
      int dsym = decode(br, dt);
      if (dsym < 0 || dsym >= 30)
        return false;
      int dist = distBase[dsym] + (int)br.readBits(distExtra[dsym]);
      size_t srcPos = out.size() - dist;
      for (int i = 0; i < length; i++)
        out.push_back(out[srcPos + i]);
    }
  }
}

bool inflate(const unsigned char *src, size_t srcLen,
             std::vector<unsigned char> &out) {
  // Skip zlib header (2 bytes) if present
  size_t offset = 0;
  if (srcLen >= 2 && (src[0] & 0x0F) == 8) {
    if ((src[0] * 256 + src[1]) % 31 == 0)
      offset = 2;
  }
  BitReader br(src + offset, srcLen - offset);
  bool bfinal;
  do {
    bfinal = br.readBits(1) != 0;
    int btype = (int)br.readBits(2);
    if (btype == 0) { // Stored
      br.bitbuf = 0;
      br.bitcount = 0;
      if (br.pos + 4 > br.size)
        return false;
      unsigned int len = br.data[br.pos] | (br.data[br.pos + 1] << 8);
      br.pos += 4;
      for (unsigned int i = 0; i < len && br.pos < br.size; i++)
        out.push_back(br.data[br.pos++]);
    } else if (btype == 1) {
      HuffTree lt, dt;
      buildFixedTrees(lt, dt);
      if (!inflateBlock(br, lt, dt, out))
        return false;
    } else if (btype == 2) {
      HuffTree lt, dt;
      if (!decodeDynTrees(br, lt, dt))
        return false;
      if (!inflateBlock(br, lt, dt, out))
        return false;
    } else
      return false;
  } while (!bfinal);
  return true;
}

} // namespace tinflate

// ========================================================================
// ANSI & UTILITY HELPERS
// ========================================================================
void enableANSI() {
#ifdef _WIN32
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut == INVALID_HANDLE_VALUE)
    return;
  DWORD dwMode = 0;
  if (!GetConsoleMode(hOut, &dwMode))
    return;
  dwMode |= 0x0004;
  SetConsoleMode(hOut, dwMode);
#endif
}

void sleepMs(int ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

std::string getTimestampUTC() {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  struct tm tmBuf;
  gmtime_s(&tmBuf, &t);
  std::ostringstream oss;
  oss << std::put_time(&tmBuf, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

std::string trim(const std::string &s) {
  size_t a = s.find_first_not_of(" \t\r\n");
  size_t b = s.find_last_not_of(" \t\r\n");
  return (a == std::string::npos) ? "" : s.substr(a, b - a + 1);
}

std::string toLower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(), ::tolower);
  return r;
}

std::string escapeJSON(const std::string &s) {
  std::string out;
  for (char c : s) {
    switch (c) {
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    case '\n':
      out += "\\n";
      break;
    case '\r':
      out += "\\r";
      break;
    case '\t':
      out += "\\t";
      break;
    default:
      if (c >= 0x20)
        out += c;
      break;
    }
  }
  return out;
}

// ========================================================================
// BANNER (Brute Force Style)
// ========================================================================
void exibirDesenho() {
  std::cout
      << "\n\x1b[1;36m  SENTINEL DATA SOLUTIONS \x1b[1;30m| \x1b[1;32mSTATUS: "
         "ACTIVE \x1b[1;30m| \x1b[1;34mENGINE: v1.0-FORENSIC\x1b[0m\n";
  std::cout << "\x1b[1;31m  " << R"( ____  _____ ____    _    ____ _____ )"
            << "  \x1b[1;33m"
            << R"( ____  ____  _____    _    _  _______ ____  )" << "\n";
  std::cout << "\x1b[1;31m  " << R"(|  _ \| ____|  _ \  / \  / ___|_   _|)"
            << "  \x1b[1;33m"
            << R"(| __ )|  _ \| ____|  / \  | |/ / ____|  _ \ )" << "\n";
  std::cout << "\x1b[1;31m  " << R"(| |_) |  _| | | | |/ _ \| |    | |  )"
            << "  \x1b[1;33m"
            << R"(|  _ \| |_) |  _|   / _ \ | ' /|  _| | |_) |)" << "\n";
  std::cout << "\x1b[1;31m  " << R"(|  _ <| |___| |_| / ___ \ |___ | |  )"
            << "  \x1b[1;33m"
            << R"(| |_) |  _ <| |___ / ___ \| . \| |___|  _ < )" << "\n";
  std::cout << "\x1b[1;31m  " << R"(|_| \_\_____|____/_/   \_\____||_|  )"
            << "  \x1b[1;33m"
            << R"(|____/|_| \_\_____/_/   \_\_|\_\_____|_| \_\)" << "\x1b[0m\n";
  std::cout << "\x1b[1;30m  "
            << "---------------------------------------------------------------"
               "---------------"
            << "\x1b[0m\n";
  std::cout << "  \x1b[1;37mFORENSIC PDF REDACTION ANALYZER \x1b[1;30m>> "
               "\x1b[38;5;208mDEVELOPED BY ZECA "
               "\x1b[1;30m>> \x1b[1;31mFOR DIDACTIC USE ONLY\x1b[0m\n";
  std::cout << "\x1b[1;30m  "
            << "---------------------------------------------------------------"
               "---------------"
            << "\x1b[0m\n";
}

// ========================================================================
// FORENSIC INGESTION (SHA-256 + Evidence Record)
// ========================================================================
std::string calculateSHA256(const std::string &filePath) {
  std::ifstream f(filePath, std::ios::binary);
  if (!f.is_open())
    return "ERROR";
  std::vector<unsigned char> data((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());
  std::string hash;
  picosha2::hash256_hex_string(data.begin(), data.end(), hash);
  return hash;
}

EvidenceRecord ingestFile(const std::string &filePath) {
  EvidenceRecord rec;
  if (!fs::exists(filePath))
    throw std::runtime_error("Arquivo nao encontrado: " + filePath);
  auto fsize = fs::file_size(filePath);
  if (fsize == 0)
    throw std::runtime_error("Arquivo vazio (0 bytes).");
  rec.filePath = fs::absolute(filePath).string();
  rec.fileName = fs::path(filePath).filename().string();
  rec.fileSize = (size_t)fsize;
  rec.sha256 = calculateSHA256(filePath);
  rec.evidenceId = rec.sha256.substr(0, 8);
  rec.accessTime = getTimestampUTC();
  auto ftime = fs::last_write_time(filePath);
  auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
      ftime - fs::file_time_type::clock::now() +
      std::chrono::system_clock::now());
  auto ct = std::chrono::system_clock::to_time_t(sctp);
  struct tm tmBuf;
  gmtime_s(&tmBuf, &ct);
  std::ostringstream oss;
  oss << std::put_time(&tmBuf, "%Y-%m-%dT%H:%M:%SZ");
  rec.creationTime = oss.str();
  rec.mimeType = "application/pdf";
  rec.integrityStatus = "VERIFIED_ORIGINAL";
  return rec;
}

// ========================================================================
// PDF RAW PARSER
// ========================================================================
class PDFParser {
public:
  std::vector<unsigned char> fileData;
  std::map<int, size_t> xrefTable; // objNum -> file offset
  int rootObjNum = 0;
  int infoObjNum = 0;
  int pageCount = 0;
  std::vector<int> pageObjNums;
  Rect defaultMediaBox = {0, 0, 612, 792};
  bool loaded = false;

  bool loadFile(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
      return false;
    fileData.assign((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    if (fileData.size() < 5)
      return false;
    // Validate PDF magic
    if (memcmp(fileData.data(), "%PDF-", 5) != 0)
      return false;
    if (!parseXref())
      bruteForceScanObjects();
    resolvePages();
    loaded = true;
    return true;
  }

  // --- Extract raw string content between obj/endobj ---
  std::string getObjectContent(int objNum) {
    auto it = xrefTable.find(objNum);
    if (it == xrefTable.end())
      return "";
    size_t pos = it->second;
    // Skip "N 0 obj"
    size_t start = findAfter(pos, "obj");
    if (start == std::string::npos)
      return "";
    start += 3;
    size_t end = findStr(start, "endobj");
    if (end == std::string::npos)
      end = fileData.size();
    return std::string(fileData.begin() + start, fileData.begin() + end);
  }

  // --- Extract stream data (decompressed if FlateDecode) ---
  std::vector<unsigned char> getStreamData(int objNum) {
    std::string content = getObjectContent(objNum);
    return extractStreamFromContent(
        content, xrefTable.count(objNum) ? xrefTable[objNum] : 0);
  }

  std::vector<unsigned char>
  extractStreamFromContent(const std::string &content, size_t baseOffset) {
    // Find "stream" keyword in the raw file data after the object dict
    size_t dictEnd = content.find("stream");
    if (dictEnd == std::string::npos)
      return {};
    size_t streamStart = dictEnd + 6;
    if (streamStart < content.size() && content[streamStart] == '\r')
      streamStart++;
    if (streamStart < content.size() && content[streamStart] == '\n')
      streamStart++;
    size_t streamEnd = content.find("endstream", streamStart);
    if (streamEnd == std::string::npos)
      streamEnd = content.size();
    // Trim trailing whitespace
    while (streamEnd > streamStart &&
           (content[streamEnd - 1] == '\r' || content[streamEnd - 1] == '\n'))
      streamEnd--;
    std::vector<unsigned char> raw(content.begin() + streamStart,
                                   content.begin() + streamEnd);
    // Check if FlateDecode
    std::string dict = content.substr(0, dictEnd);
    if (dict.find("/FlateDecode") != std::string::npos ||
        dict.find("/Fl") != std::string::npos) {
      std::vector<unsigned char> decompressed;
      if (tinflate::inflate(raw.data(), raw.size(), decompressed))
        return decompressed;
    }
    return raw;
  }

  // --- Get value for a PDF dictionary key ---
  std::string getDictValue(const std::string &dict, const std::string &key) {
    size_t pos = dict.find(key);
    if (pos == std::string::npos)
      return "";
    pos += key.size();
    while (pos < dict.size() &&
           (dict[pos] == ' ' || dict[pos] == '\r' || dict[pos] == '\n'))
      pos++;
    if (pos >= dict.size())
      return "";
    // Detect value type
    if (dict[pos] == '/') { // Name
      size_t end = pos + 1;
      while (end < dict.size() && dict[end] != ' ' && dict[end] != '/' &&
             dict[end] != '\r' && dict[end] != '\n' && dict[end] != '>' &&
             dict[end] != '[' && dict[end] != ']')
        end++;
      return dict.substr(pos, end - pos);
    }
    if (dict[pos] == '(') { // String literal
      int depth = 1;
      size_t end = pos + 1;
      while (end < dict.size() && depth > 0) {
        if (dict[end] == '(' && (end == 0 || dict[end - 1] != '\\'))
          depth++;
        else if (dict[end] == ')' && (end == 0 || dict[end - 1] != '\\'))
          depth--;
        end++;
      }
      return dict.substr(pos + 1, end - pos - 2);
    }
    if (dict[pos] == '<' && pos + 1 < dict.size() &&
        dict[pos + 1] == '<') { // Sub-dictionary
      int depth = 1;
      size_t end = pos + 2;
      while (end + 1 < dict.size() && depth > 0) {
        if (dict[end] == '<' && dict[end + 1] == '<') {
          depth++;
          end += 2;
          continue;
        }
        if (dict[end] == '>' && dict[end + 1] == '>') {
          depth--;
          end += 2;
          continue;
        }
        end++;
      }
      return dict.substr(pos, end - pos);
    }
    if (dict[pos] == '[') { // Array
      int depth = 1;
      size_t end = pos + 1;
      while (end < dict.size() && depth > 0) {
        if (dict[end] == '[')
          depth++;
        else if (dict[end] == ']')
          depth--;
        end++;
      }
      return dict.substr(pos, end - pos);
    }
    // Number or reference (N 0 R)
    size_t end = pos;
    while (end < dict.size() && dict[end] != '/' && dict[end] != '>' &&
           dict[end] != '\r' && dict[end] != '\n')
      end++;
    return trim(dict.substr(pos, end - pos));
  }

  // --- Resolve an indirect reference "N 0 R" -> objNum ---
  int resolveRef(const std::string &val) {
    if (val.empty())
      return -1;
    // Check if it's "N 0 R"
    std::istringstream iss(val);
    int n, g;
    std::string r;
    if (iss >> n >> g >> r && r == "R")
      return n;
    return -1;
  }

  // --- Extract text spans from a page's content stream ---
  std::vector<TextSpan> extractTextFromPage(int pageIdx) {
    std::vector<TextSpan> spans;
    if (pageIdx < 0 || pageIdx >= (int)pageObjNums.size())
      return spans;
    std::string pageContent = getObjectContent(pageObjNums[pageIdx]);
    // Get Contents reference
    std::string contentsVal = getDictValue(pageContent, "/Contents");
    std::vector<unsigned char> streamData;
    if (contentsVal.find("[") != std::string::npos) {
      // Array of content stream refs — strip brackets
      std::string inner = contentsVal;
      size_t bs = inner.find('[');
      if (bs != std::string::npos)
        inner = inner.substr(bs + 1);
      size_t be = inner.rfind(']');
      if (be != std::string::npos)
        inner = inner.substr(0, be);
      std::istringstream iss(inner);
      int n, g;
      std::string tok;
      while (iss >> n) {
        if (iss >> g >> tok && (tok == "R" || tok.find("R") == 0)) {
          auto sd = getStreamData(n);
          streamData.insert(streamData.end(), sd.begin(), sd.end());
          streamData.push_back('\n');
        }
      }
    } else {
      int ref = resolveRef(contentsVal);
      if (ref > 0)
        streamData = getStreamData(ref);
    }
    if (streamData.empty())
      return spans;
    std::string stream(streamData.begin(), streamData.end());
    parseContentStreamForText(stream, spans);
    return spans;
  }

  // --- Extract vector rectangles from a page's content stream ---
  std::vector<VectorRect> extractVectorsFromPage(int pageIdx) {
    std::vector<VectorRect> rects;
    if (pageIdx < 0 || pageIdx >= (int)pageObjNums.size())
      return rects;
    std::string pageContent = getObjectContent(pageObjNums[pageIdx]);
    std::string contentsVal = getDictValue(pageContent, "/Contents");
    std::vector<unsigned char> streamData;
    if (contentsVal.find("[") != std::string::npos) {
      std::string inner = contentsVal;
      size_t bs = inner.find('[');
      if (bs != std::string::npos)
        inner = inner.substr(bs + 1);
      size_t be = inner.rfind(']');
      if (be != std::string::npos)
        inner = inner.substr(0, be);
      std::istringstream iss(inner);
      int n, g;
      std::string tok;
      while (iss >> n) {
        if (iss >> g >> tok && (tok == "R" || tok.find("R") == 0)) {
          auto sd = getStreamData(n);
          streamData.insert(streamData.end(), sd.begin(), sd.end());
          streamData.push_back('\n');
        }
      }
    } else {
      int ref = resolveRef(contentsVal);
      if (ref > 0)
        streamData = getStreamData(ref);
    }
    if (streamData.empty())
      return rects;
    std::string stream(streamData.begin(), streamData.end());
    parseContentStreamForVectors(stream, rects);
    return rects;
  }

  // --- Get page MediaBox ---
  Rect getPageMediaBox(int pageIdx) {
    if (pageIdx < 0 || pageIdx >= (int)pageObjNums.size())
      return defaultMediaBox;
    std::string content = getObjectContent(pageObjNums[pageIdx]);
    std::string mbVal = getDictValue(content, "/MediaBox");
    if (mbVal.empty())
      return defaultMediaBox;
    return parseRect(mbVal);
  }

  // --- Get page CropBox ---
  Rect getPageCropBox(int pageIdx) {
    if (pageIdx < 0 || pageIdx >= (int)pageObjNums.size())
      return getPageMediaBox(pageIdx);
    std::string content = getObjectContent(pageObjNums[pageIdx]);
    std::string cbVal = getDictValue(content, "/CropBox");
    if (cbVal.empty())
      return getPageMediaBox(pageIdx);
    return parseRect(cbVal);
  }

  // --- Extract embedded images from a page ---
  std::vector<ImageInfo> extractImagesFromPage(int pageIdx) {
    std::vector<ImageInfo> images;
    if (pageIdx < 0 || pageIdx >= (int)pageObjNums.size())
      return images;
    std::string pageContent = getObjectContent(pageObjNums[pageIdx]);
    std::string resVal = getDictValue(pageContent, "/Resources");
    int resRef = resolveRef(resVal);
    std::string resDict = resRef > 0 ? getObjectContent(resRef) : resVal;
    std::string xObjVal = getDictValue(resDict, "/XObject");
    int xoRef = resolveRef(xObjVal);
    std::string xObjDict = xoRef > 0 ? getObjectContent(xoRef) : xObjVal;
    if (xObjDict.empty())
      return images;
    // Parse XObject dict for image references
    size_t pos = 0;
    while (pos < xObjDict.size()) {
      pos = xObjDict.find('/', pos);
      if (pos == std::string::npos)
        break;
      size_t nameEnd = pos + 1;
      while (nameEnd < xObjDict.size() && xObjDict[nameEnd] != ' ' &&
             xObjDict[nameEnd] != '/')
        nameEnd++;
      std::string ref =
          getDictValue(xObjDict, xObjDict.substr(pos, nameEnd - pos));
      int imgObjNum = resolveRef(ref);
      if (imgObjNum > 0) {
        std::string imgDict = getObjectContent(imgObjNum);
        if (imgDict.find("/Subtype /Image") != std::string::npos ||
            imgDict.find("/Subtype/Image") != std::string::npos) {
          ImageInfo img;
          img.page = pageIdx;
          std::string w = getDictValue(imgDict, "/Width");
          std::string h = getDictValue(imgDict, "/Height");
          img.width = w.empty() ? 0 : std::stoi(trim(w));
          img.height = h.empty() ? 0 : std::stoi(trim(h));
          img.colorSpace = getDictValue(imgDict, "/ColorSpace");
          img.filter = getDictValue(imgDict, "/Filter");
          std::string bpc = getDictValue(imgDict, "/BitsPerComponent");
          img.bitsPerComponent = bpc.empty() ? 8 : std::stoi(trim(bpc));
          img.data = getStreamData(imgObjNum);
          Rect mb = getPageMediaBox(pageIdx);
          img.bbox = mb;
          images.push_back(img);
        }
      }
      pos = nameEnd;
    }
    return images;
  }

  // --- Get PDF metadata (Info dictionary) ---
  MetadataResult getMetadata() {
    MetadataResult meta;
    if (infoObjNum <= 0)
      return meta;
    std::string content = getObjectContent(infoObjNum);
    auto extract = [&](const std::string &key) -> std::string {
      return getDictValue(content, key);
    };
    meta.standard["Title"] = extract("/Title");
    meta.standard["Author"] = extract("/Author");
    meta.standard["Subject"] = extract("/Subject");
    meta.standard["Creator"] = extract("/Creator");
    meta.standard["Producer"] = extract("/Producer");
    meta.standard["CreationDate"] = extract("/CreationDate");
    meta.standard["ModDate"] = extract("/ModDate");
    // Check for suspicious creators
    std::vector<std::string> suspicious = {"Photoshop", "Illustrator", "GIMP",
                                           "CorelDraw", "Paint"};
    std::string creator = toLower(meta.standard["Creator"]);
    std::string producer = toLower(meta.standard["Producer"]);
    for (auto &s : suspicious) {
      if (creator.find(toLower(s)) != std::string::npos ||
          producer.find(toLower(s)) != std::string::npos)
        meta.suspiciousTags.push_back("Graphic Editing Software: " + s);
    }
    return meta;
  }

private:
  size_t findStr(size_t from, const std::string &needle) {
    auto it = std::search(fileData.begin() + from, fileData.end(),
                          needle.begin(), needle.end());
    return it == fileData.end() ? std::string::npos
                                : std::distance(fileData.begin(), it);
  }

  size_t findAfter(size_t from, const std::string &needle) {
    return findStr(from, needle);
  }

  size_t rfindStr(const std::string &needle) {
    auto it = std::find_end(fileData.begin(), fileData.end(), needle.begin(),
                            needle.end());
    return it == fileData.end() ? std::string::npos
                                : std::distance(fileData.begin(), it);
  }

  bool parseXref() {
    // Find startxref from end of file
    size_t sxr = rfindStr("startxref");
    if (sxr == std::string::npos)
      return false;
    std::string tail(fileData.begin() + sxr + 9, fileData.end());
    std::istringstream iss(tail);
    size_t xrefOffset;
    if (!(iss >> xrefOffset))
      return false;
    if (xrefOffset >= fileData.size())
      return false;
    // Check if it's a traditional xref table or xref stream
    std::string marker(fileData.begin() + xrefOffset,
                       fileData.begin() +
                           std::min(xrefOffset + 4, fileData.size()));
    if (marker.substr(0, 4) == "xref")
      return parseTraditionalXref(xrefOffset);
    // Xref stream (try brute force)
    return false;
  }

  bool parseTraditionalXref(size_t offset) {
    size_t pos = offset + 4;
    while (pos < fileData.size() &&
           (fileData[pos] == '\r' || fileData[pos] == '\n' ||
            fileData[pos] == ' '))
      pos++;
    while (pos < fileData.size()) {
      std::string line;
      size_t lineStart = pos;
      while (pos < fileData.size() && fileData[pos] != '\r' &&
             fileData[pos] != '\n')
        pos++;
      line = std::string(fileData.begin() + lineStart, fileData.begin() + pos);
      while (pos < fileData.size() &&
             (fileData[pos] == '\r' || fileData[pos] == '\n'))
        pos++;
      if (line.find("trailer") != std::string::npos)
        break;
      std::istringstream lss(line);
      int firstObj, count;
      if (lss >> firstObj >> count) {
        for (int i = 0; i < count && pos < fileData.size(); i++) {
          lineStart = pos;
          while (pos < fileData.size() && fileData[pos] != '\r' &&
                 fileData[pos] != '\n')
            pos++;
          std::string entry(fileData.begin() + lineStart,
                            fileData.begin() + pos);
          while (pos < fileData.size() &&
                 (fileData[pos] == '\r' || fileData[pos] == '\n'))
            pos++;
          std::istringstream ess(entry);
          size_t off;
          int gen;
          char type;
          if (ess >> off >> gen >> type && type == 'n')
            xrefTable[firstObj + i] = off;
        }
      }
    }
    // Parse trailer
    size_t trailerPos = findStr(offset, "trailer");
    if (trailerPos != std::string::npos) {
      size_t dictStart = findStr(trailerPos, "<<");
      size_t dictEnd = findStr(dictStart, ">>");
      if (dictStart != std::string::npos && dictEnd != std::string::npos) {
        std::string trailer(fileData.begin() + dictStart,
                            fileData.begin() + dictEnd + 2);
        std::string rootVal = getDictValue(trailer, "/Root");
        rootObjNum = resolveRef(rootVal);
        std::string infoVal = getDictValue(trailer, "/Info");
        infoObjNum = resolveRef(infoVal);
      }
    }
    return !xrefTable.empty();
  }

  void bruteForceScanObjects() {
    // Scan entire file for "N 0 obj" patterns
    for (size_t i = 0; i + 5 < fileData.size(); i++) {
      if (fileData[i] >= '0' && fileData[i] <= '9') {
        size_t numStart = i;
        while (i < fileData.size() && fileData[i] >= '0' && fileData[i] <= '9')
          i++;
        if (i < fileData.size() && fileData[i] == ' ') {
          i++;
          if (i < fileData.size() && fileData[i] >= '0' && fileData[i] <= '9') {
            i++;
            if (i + 3 < fileData.size() && fileData[i] == ' ' &&
                fileData[i + 1] == 'o' && fileData[i + 2] == 'b' &&
                fileData[i + 3] == 'j') {
              int objNum = std::stoi(std::string(fileData.begin() + numStart,
                                                 fileData.begin() + numStart +
                                                     (i - 2 - numStart)));
              xrefTable[objNum] = numStart;
            }
          }
        }
      }
    }
    // Try to find Root from first Catalog object
    for (auto &[num, off] : xrefTable) {
      std::string content = getObjectContent(num);
      if (content.find("/Type /Catalog") != std::string::npos ||
          content.find("/Type/Catalog") != std::string::npos) {
        rootObjNum = num;
        break;
      }
    }
  }

  void resolvePages() {
    if (rootObjNum <= 0)
      return;
    std::string root = getObjectContent(rootObjNum);
    std::string pagesVal = getDictValue(root, "/Pages");
    int pagesRef = resolveRef(pagesVal);
    if (pagesRef <= 0)
      return;
    collectPages(pagesRef);
    pageCount = (int)pageObjNums.size();
  }

  void collectPages(int objNum) {
    std::string content = getObjectContent(objNum);
    if (content.find("/Type /Page ") != std::string::npos ||
        content.find("/Type /Page\r") != std::string::npos ||
        content.find("/Type /Page\n") != std::string::npos ||
        content.find("/Type/Page ") != std::string::npos ||
        content.find("/Type/Page\r") != std::string::npos ||
        content.find("/Type/Page\n") != std::string::npos ||
        content.find("/Type/Page>") != std::string::npos) {
      if (content.find("/Type /Pages") == std::string::npos &&
          content.find("/Type/Pages") == std::string::npos) {
        pageObjNums.push_back(objNum);
        return;
      }
    }
    // It's a Pages node - traverse Kids
    std::string kidsVal = getDictValue(content, "/Kids");
    if (kidsVal.empty())
      return;
    // Strip brackets and parse references
    std::string kidsInner = kidsVal;
    // Remove [ and ]
    size_t bStart = kidsInner.find('[');
    if (bStart != std::string::npos)
      kidsInner = kidsInner.substr(bStart + 1);
    size_t bEnd = kidsInner.rfind(']');
    if (bEnd != std::string::npos)
      kidsInner = kidsInner.substr(0, bEnd);
    std::istringstream iss(kidsInner);
    int n, g;
    std::string tok;
    while (iss >> n) {
      if (iss >> g >> tok && (tok == "R" || tok.find("R") == 0))
        collectPages(n);
    }
  }

  Rect parseRect(const std::string &val) {
    Rect r;
    std::string s = val;
    // Remove [ ]
    size_t a = s.find('[');
    size_t b = s.find(']');
    if (a != std::string::npos && b != std::string::npos)
      s = s.substr(a + 1, b - a - 1);
    std::istringstream iss(s);
    iss >> r.x0 >> r.y0 >> r.x1 >> r.y1;
    return r;
  }

  // --- Content Stream Text Parser ---
  void parseContentStreamForText(const std::string &stream,
                                 std::vector<TextSpan> &spans) {
    std::vector<std::string> tokens;
    tokenizeContentStream(stream, tokens);
    double tx = 0, ty = 0; // Text position
    double fontSize = 12;
    double tm[6] = {1, 0, 0, 1, 0, 0}; // Text matrix
    bool inText = false;
    int fillColor = 0;
    std::vector<double> numStack;

    for (size_t i = 0; i < tokens.size(); i++) {
      const std::string &tok = tokens[i];
      if (tok == "BT") {
        inText = true;
        tx = 0;
        ty = 0;
        tm[0] = 1;
        tm[1] = 0;
        tm[2] = 0;
        tm[3] = 1;
        tm[4] = 0;
        tm[5] = 0;
        numStack.clear();
        continue;
      }
      if (tok == "ET") {
        inText = false;
        numStack.clear();
        continue;
      }
      // Try to parse as number
      bool isNum = false;
      double numVal = 0;
      try {
        numVal = std::stod(tok);
        isNum = true;
      } catch (...) {
      }
      if (isNum) {
        numStack.push_back(numVal);
        continue;
      }
      if (!inText && tok != "rg" && tok != "g" && tok != "RG" && tok != "G") {
        numStack.clear();
        continue;
      }
      if (tok == "Tf" && numStack.size() >= 1) {
        fontSize = numStack.back();
        numStack.clear();
      } else if (tok == "Td" || tok == "TD") {
        if (numStack.size() >= 2) {
          tx += numStack[numStack.size() - 2];
          ty += numStack[numStack.size() - 1];
        }
        numStack.clear();
      } else if (tok == "Tm") {
        if (numStack.size() >= 6) {
          for (int j = 0; j < 6; j++)
            tm[j] = numStack[numStack.size() - 6 + j];
          tx = tm[4];
          ty = tm[5];
        }
        numStack.clear();
      } else if (tok == "T*") {
        ty -= fontSize;
        numStack.clear();
      } else if (tok == "rg" && numStack.size() >= 3) {
        int rr = (int)(numStack[numStack.size() - 3] * 255);
        int gg = (int)(numStack[numStack.size() - 2] * 255);
        int bb = (int)(numStack[numStack.size() - 1] * 255);
        fillColor = (rr << 16) | (gg << 8) | bb;
        numStack.clear();
      } else if (tok == "g" && numStack.size() >= 1) {
        int gray = (int)(numStack.back() * 255);
        fillColor = (gray << 16) | (gray << 8) | gray;
        numStack.clear();
      } else if (tok == "Tj" || tok == "'" || tok == "\"") {
        // Last string on stack
        if (i > 0 && tokens[i - 1].front() == '(') {
          std::string text =
              tokens[i - 1].substr(1, tokens[i - 1].size() - 2); // strip ()
          TextSpan span;
          span.text = text;
          span.fontSize = fontSize;
          span.colorRGB = fillColor;
          double textWidth = text.size() * fontSize * 0.5;
          span.bbox = {tx, ty, tx + textWidth, ty + fontSize};
          spans.push_back(span);
          if (tok != "Tj")
            ty -= fontSize; // ' and " advance line
        }
        numStack.clear();
      } else if (tok == "TJ") {
        // Array of strings with kerning: [(text) kern (text)]
        // Look back for array content
        std::string combined;
        for (int j = (int)i - 1; j >= 0 && tokens[j] != "["; j--) {
          if (!tokens[j].empty() && tokens[j].front() == '(') {
            std::string t = tokens[j].substr(1, tokens[j].size() - 2);
            combined = t + combined;
          }
        }
        if (!combined.empty()) {
          TextSpan span;
          span.text = combined;
          span.fontSize = fontSize;
          span.colorRGB = fillColor;
          double textWidth = combined.size() * fontSize * 0.5;
          span.bbox = {tx, ty, tx + textWidth, ty + fontSize};
          spans.push_back(span);
        }
        numStack.clear();
      } else {
        numStack.clear();
      }
    }
  }

  // --- Content Stream Vector Parser ---
  void parseContentStreamForVectors(const std::string &stream,
                                    std::vector<VectorRect> &rects) {
    std::vector<std::string> tokens;
    tokenizeContentStream(stream, tokens);
    double fillR = 0, fillG = 0, fillB = 0;
    std::vector<double> numStack;
    struct PathState {
      double x, y, w, h;
      bool isRect;
    };
    std::vector<PathState> paths;

    for (size_t i = 0; i < tokens.size(); i++) {
      const std::string &tok = tokens[i];
      bool isNum = false;
      double numVal = 0;
      try {
        numVal = std::stod(tok);
        isNum = true;
      } catch (...) {
      }
      if (isNum) {
        numStack.push_back(numVal);
        continue;
      }
      if (tok == "rg" && numStack.size() >= 3) {
        fillR = numStack[numStack.size() - 3];
        fillG = numStack[numStack.size() - 2];
        fillB = numStack[numStack.size() - 1];
        numStack.clear();
      } else if (tok == "g" && numStack.size() >= 1) {
        fillR = fillG = fillB = numStack.back();
        numStack.clear();
      } else if (tok == "k" && numStack.size() >= 4) {
        // CMYK to RGB approximation
        double c = numStack[numStack.size() - 4],
               m = numStack[numStack.size() - 3];
        double y = numStack[numStack.size() - 2],
               k = numStack[numStack.size() - 1];
        fillR = (1 - c) * (1 - k);
        fillG = (1 - m) * (1 - k);
        fillB = (1 - y) * (1 - k);
        numStack.clear();
      } else if (tok == "re" && numStack.size() >= 4) {
        PathState ps;
        ps.x = numStack[numStack.size() - 4];
        ps.y = numStack[numStack.size() - 3];
        ps.w = numStack[numStack.size() - 2];
        ps.h = numStack[numStack.size() - 1];
        ps.isRect = true;
        paths.push_back(ps);
        numStack.clear();
      } else if (tok == "f" || tok == "F" || tok == "f*") {
        for (auto &p : paths) {
          if (p.isRect) {
            VectorRect vr;
            vr.bbox = {p.x, p.y, p.x + p.w, p.y + p.h};
            // Normalize (ensure x0<x1, y0<y1)
            if (vr.bbox.x0 > vr.bbox.x1)
              std::swap(vr.bbox.x0, vr.bbox.x1);
            if (vr.bbox.y0 > vr.bbox.y1)
              std::swap(vr.bbox.y0, vr.bbox.y1);
            vr.r = fillR;
            vr.g = fillG;
            vr.b = fillB;
            vr.isFilled = true;
            rects.push_back(vr);
          }
        }
        paths.clear();
        numStack.clear();
      } else if (tok == "S" || tok == "s" || tok == "n") {
        paths.clear();
        numStack.clear();
      } else if (tok == "q" || tok == "Q") {
        numStack.clear();
      } else {
        numStack.clear();
      }
    }
  }

  // --- Tokenizer for PDF content streams ---
  void tokenizeContentStream(const std::string &stream,
                             std::vector<std::string> &tokens) {
    size_t i = 0;
    while (i < stream.size()) {
      char c = stream[i];
      if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
        i++;
        continue;
      }
      if (c == '%') {
        while (i < stream.size() && stream[i] != '\n')
          i++;
        continue;
      }
      if (c == '(') {
        // String literal
        int depth = 1;
        size_t start = i;
        i++;
        while (i < stream.size() && depth > 0) {
          if (stream[i] == '\\') {
            i += 2;
            continue;
          }
          if (stream[i] == '(')
            depth++;
          if (stream[i] == ')')
            depth--;
          i++;
        }
        tokens.push_back(stream.substr(start, i - start));
        continue;
      }
      if (c == '<' && i + 1 < stream.size() && stream[i + 1] != '<') {
        // Hex string
        size_t start = i;
        i++;
        while (i < stream.size() && stream[i] != '>')
          i++;
        if (i < stream.size())
          i++;
        tokens.push_back(stream.substr(start, i - start));
        continue;
      }
      if (c == '[' || c == ']') {
        tokens.push_back(std::string(1, c));
        i++;
        continue;
      }
      if (c == '<' && i + 1 < stream.size() && stream[i + 1] == '<') {
        tokens.push_back("<<");
        i += 2;
        continue;
      }
      if (c == '>' && i + 1 < stream.size() && stream[i + 1] == '>') {
        tokens.push_back(">>");
        i += 2;
        continue;
      }
      if (c == '/') {
        size_t start = i;
        i++;
        while (i < stream.size() && stream[i] != ' ' && stream[i] != '/' &&
               stream[i] != '\r' && stream[i] != '\n' && stream[i] != '[' &&
               stream[i] != '(' && stream[i] != '<')
          i++;
        tokens.push_back(stream.substr(start, i - start));
        continue;
      }
      // Number or operator
      size_t start = i;
      while (i < stream.size() && stream[i] != ' ' && stream[i] != '\t' &&
             stream[i] != '\r' && stream[i] != '\n' && stream[i] != '(' &&
             stream[i] != ')' && stream[i] != '[' && stream[i] != ']' &&
             stream[i] != '/' && stream[i] != '<' && stream[i] != '>')
        i++;
      if (i > start)
        tokens.push_back(stream.substr(start, i - start));
    }
  }
};

// ========================================================================
// RASTER DETECTION (GDI+ based — replaces OpenCV)
// ========================================================================
namespace RasterAnalysis {

struct RasterCandidate {
  Rect bbox;
  double solidity = 0;
  int pixelWidth = 0, pixelHeight = 0;
};

std::vector<RasterCandidate> findBlackRects(const unsigned char *grayPixels,
                                            int width, int height,
                                            double zoom) {
  std::vector<RasterCandidate> results;
  if (!grayPixels || width <= 0 || height <= 0)
    return results;
  std::vector<unsigned char> binary(width * height, 0);
  for (int i = 0; i < width * height; i++)
    binary[i] = (grayPixels[i] < 10) ? 1 : 0;
  int dilationIters = 2;
  for (int iter = 0; iter < dilationIters; iter++) {
    std::vector<unsigned char> dilated = binary;
    for (int y = 1; y < height - 1; y++)
      for (int x = 1; x < width - 1; x++)
        if (binary[y * width + x])
          for (int dy = -1; dy <= 1; dy++)
            for (int dx = -1; dx <= 1; dx++)
              dilated[(y + dy) * width + (x + dx)] = 1;
    binary = dilated;
  }
  std::vector<int> labels(width * height, 0);
  int nextLabel = 1;
  struct CompInfo {
    int minX, minY, maxX, maxY, area;
  };
  std::map<int, CompInfo> comps;
  for (int y = 0; y < height; y++) {
    for (int x = 0; x < width; x++) {
      if (binary[y * width + x] == 0)
        continue;
      int left = (x > 0) ? labels[y * width + x - 1] : 0;
      int up = (y > 0) ? labels[(y - 1) * width + x] : 0;
      int label = 0;
      if (left > 0 && up > 0) {
        label = std::min(left, up);
        if (left != up) {
          int old = std::max(left, up);
          for (int i = 0; i < y * width + x; i++)
            if (labels[i] == old)
              labels[i] = label;
          if (comps.count(old)) {
            auto &a = comps[label];
            auto &b = comps[old];
            a.minX = std::min(a.minX, b.minX);
            a.minY = std::min(a.minY, b.minY);
            a.maxX = std::max(a.maxX, b.maxX);
            a.maxY = std::max(a.maxY, b.maxY);
            a.area += b.area;
            comps.erase(old);
          }
        }
      } else if (left > 0)
        label = left;
      else if (up > 0)
        label = up;
      else {
        label = nextLabel++;
        comps[label] = {x, y, x, y, 0};
      }
      labels[y * width + x] = label;
      auto &c = comps[label];
      c.minX = std::min(c.minX, x);
      c.minY = std::min(c.minY, y);
      c.maxX = std::max(c.maxX, x);
      c.maxY = std::max(c.maxY, y);
      c.area++;
    }
  }
  for (auto &[id, c] : comps) {
    int w = c.maxX - c.minX + 1, h = c.maxY - c.minY + 1;
    if (w < 20 || h < 10)
      continue;
    if ((double)w / h < 0.2)
      continue;
    if ((double)c.area / (w * h) < 0.85)
      continue;
    if (w > width * 0.95 || h > height * 0.95)
      continue;
    // Check solidity on the INNER region (erode back)
    // Dilation expands the rect by 'dilationIters' pixels on each side.
    // To check if it's truly solid black, we should check the core.
    int pad = dilationIters * 2;
    int innerMinX = std::max(0, c.minX + pad);
    int innerMinY = std::max(0, c.minY + pad);
    int innerMaxX = std::min(width - 1, c.maxX - pad);
    int innerMaxY = std::min(height - 1, c.maxY - pad);

    int innerW = innerMaxX - innerMinX + 1;
    int innerH = innerMaxY - innerMinY + 1;

    // Calculate original solidity for fallback/logging
    int solidCount = 0;
    for (int py = c.minY; py <= c.maxY; py++)
      for (int px = c.minX; px <= c.maxX; px++)
        if (grayPixels[py * width + px] < 10)
          solidCount++;
    double solidity = (double)solidCount / (w * h);

    // improved solidity check
    if (innerW > 0 && innerH > 0) {
      int innerSolid = 0;
      for (int py = innerMinY; py <= innerMaxY; py++) {
        for (int px = innerMinX; px <= innerMaxX; px++) {
          if (grayPixels[py * width + px] < 10) // Check absolute original pixel
            innerSolid++;
        }
      }
      double innerSolidity = (double)innerSolid / (innerW * innerH);
      if (innerSolidity < 0.95)
        continue;
    } else {
      // if eroded to nothing, use the original solidity but with a closer look
      if (solidity < 0.90)
        continue;
    }
    RasterCandidate rc;
    rc.bbox = {c.minX / zoom, c.minY / zoom, (c.maxX + 1) / zoom,
               (c.maxY + 1) / zoom};
    rc.solidity = solidity;
    rc.pixelWidth = w;
    rc.pixelHeight = h;
    results.push_back(rc);
  }
  return results;
}

std::vector<RasterCandidate>
analyzeImage(const std::vector<unsigned char> &imageData, int imgWidth,
             int imgHeight, const std::string &filter,
             const std::string &colorSpace, int bpc) {
  std::vector<RasterCandidate> results;
  std::vector<unsigned char> grayPixels;
  int w = imgWidth, h = imgHeight;
  if (filter.find("DCTDecode") != std::string::npos ||
      filter.find("DCT") != std::string::npos) {
    ULONG_PTR gdiplusToken;
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    {
      HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, imageData.size());
      if (hMem) {
        void *pMem = GlobalLock(hMem);
        memcpy(pMem, imageData.data(), imageData.size());
        GlobalUnlock(hMem);
        IStream *pStream = NULL;
        CreateStreamOnHGlobal(hMem, TRUE, &pStream);
        Gdiplus::Bitmap *bmp = Gdiplus::Bitmap::FromStream(pStream);
        if (bmp && bmp->GetLastStatus() == Gdiplus::Ok) {
          w = bmp->GetWidth();
          h = bmp->GetHeight();
          grayPixels.resize(w * h);
          for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++) {
              Gdiplus::Color color;
              bmp->GetPixel(x, y, &color);
              grayPixels[y * w + x] =
                  (unsigned char)(0.299 * color.GetR() + 0.587 * color.GetG() +
                                  0.114 * color.GetB());
            }
          delete bmp;
        }
        if (pStream)
          pStream->Release();
      }
    }
    Gdiplus::GdiplusShutdown(gdiplusToken);
  } else if (w > 0 && h > 0 && !imageData.empty()) {
    bool isGray = colorSpace.find("Gray") != std::string::npos;
    int ch = isGray ? 1 : 3;
    if ((int)imageData.size() >= w * h * ch) {
      grayPixels.resize(w * h);
      for (int i = 0; i < w * h; i++)
        grayPixels[i] = isGray ? imageData[i]
                               : (unsigned char)(0.299 * imageData[i * ch] +
                                                 0.587 * imageData[i * ch + 1] +
                                                 0.114 * imageData[i * ch + 2]);
    }
  }
  if (!grayPixels.empty())
    results = findBlackRects(grayPixels.data(), w, h, 1.0);
  return results;
}
} // namespace RasterAnalysis

// ========================================================================
// REDACTION FINDER
// ========================================================================
std::vector<RedactionCandidate> findAllCandidates(PDFParser &parser,
                                                  int pageIdx) {
  std::vector<RedactionCandidate> candidates;
  Rect mediaBox = parser.getPageMediaBox(pageIdx);
  double pageArea = mediaBox.area();
  auto vectors = parser.extractVectorsFromPage(pageIdx);
  int vid = 0;
  for (auto &v : vectors) {
    if (!v.isFilled)
      continue;
    double vArea = v.bbox.area();
    bool isBlack = (v.r < 0.05 && v.g < 0.05 && v.b < 0.05);
    bool isWhite = (v.r > 0.95 && v.g > 0.95 && v.b > 0.95);
    if (vArea > pageArea * 0.90 && !isBlack)
      continue;
    if (v.bbox.width() < 5 || v.bbox.height() < 5)
      continue;
    if (!isBlack && !isWhite)
      continue;
    RedactionCandidate rc;
    rc.id = "P" + std::to_string(pageIdx) + "_V" + std::to_string(vid++);
    rc.bbox = v.bbox;
    rc.colorR = v.r;
    rc.colorG = v.g;
    rc.colorB = v.b;
    rc.confidence = isBlack ? "HIGH" : "MEDIUM";
    rc.type = "VECTOR_OVERLAY";
    rc.page = pageIdx;
    candidates.push_back(rc);
  }
  auto images = parser.extractImagesFromPage(pageIdx);
  int rid = 0;
  for (auto &img : images) {
    auto rCands = RasterAnalysis::analyzeImage(img.data, img.width, img.height,
                                               img.filter, img.colorSpace,
                                               img.bitsPerComponent);
    for (auto &rc : rCands) {
      RedactionCandidate cand;
      cand.id = "P" + std::to_string(pageIdx) + "_R" + std::to_string(rid++);
      cand.bbox = rc.bbox;
      cand.colorR = 0;
      cand.colorG = 0;
      cand.colorB = 0;
      cand.confidence = "HIGH";
      cand.type = "RASTER_DETECTED";
      cand.page = pageIdx;
      candidates.push_back(cand);
    }
  }
  return candidates;
}

// ========================================================================
// REDACTION BREAKER
// ========================================================================
std::vector<Breach>
breakRedactions(PDFParser &parser, int pageIdx,
                const std::vector<RedactionCandidate> &candidates) {
  std::vector<Breach> breaches;
  auto textSpans = parser.extractTextFromPage(pageIdx);
  for (auto &cand : candidates) {
    std::vector<std::string> hidden;
    for (auto &span : textSpans) {
      Rect inter = cand.bbox.intersect(span.bbox);
      if (inter.isEmpty())
        continue;
      double tArea = span.bbox.area();
      if (tArea > 0 && inter.area() / tArea > 0.10)
        hidden.push_back(span.text);
    }
    if (!hidden.empty()) {
      Breach b;
      b.type = "VISUAL_ONLY_REDACTION";
      b.severity = "CRITICAL";
      b.status = "BROKEN";
      b.candidateId = cand.id;
      b.page = pageIdx;
      b.bbox = cand.bbox;
      std::string combined;
      for (auto &s : hidden) {
        if (!combined.empty())
          combined += " ";
        combined += s;
      }
      b.recoveredText = combined;
      b.justification = "Texto persistente no content stream (operador Tj) "
                        "apenas oculto por sobreposicao vetorial (Z-order).";
      breaches.push_back(b);
    }
  }
  return breaches;
}

// ========================================================================
// DEEP FORENSICS
// ========================================================================
std::vector<Breach> scanInvisibleText(PDFParser &parser, int pageIdx) {
  std::vector<Breach> findings;
  for (auto &span : parser.extractTextFromPage(pageIdx)) {
    if (trim(span.text).empty())
      continue;
    int r = (span.colorRGB >> 16) & 0xFF, g = (span.colorRGB >> 8) & 0xFF,
        bv = span.colorRGB & 0xFF;
    bool isW = (r > 242 && g > 242 && bv > 242), isM = (span.fontSize < 1.0);
    if (isW || isM) {
      Breach b;
      b.type = "INVISIBLE_TEXT";
      b.severity = "HIGH";
      b.status = "EXPOSED";
      b.candidateId = "P" + std::to_string(pageIdx) + "_INV";
      b.page = pageIdx;
      b.bbox = span.bbox;
      b.recoveredText = span.text;
      b.justification =
          isW ? "Texto invisivel (WHITE_ON_WHITE) detectado no stream."
              : "Texto invisivel (MICRO_TEXT <1pt) detectado no stream.";
      findings.push_back(b);
    }
  }
  return findings;
}

std::vector<Breach> scanOutOfBounds(PDFParser &parser, int pageIdx) {
  std::vector<Breach> findings;
  Rect crop = parser.getPageCropBox(pageIdx);
  if (crop.area() <= 0)
    return findings; // No CropBox defined, skip
  for (auto &span : parser.extractTextFromPage(pageIdx)) {
    if (trim(span.text).empty())
      continue;
    double spanArea = span.bbox.area();
    if (spanArea <= 0)
      continue;
    Rect inter = crop.intersect(span.bbox);
    double overlapArea = inter.isEmpty() ? 0.0 : inter.area();
    double overlapRatio = overlapArea / spanArea;
    // Flag if text is fully outside OR mostly outside CropBox (<30% visible)
    if (overlapRatio < 0.30) {
      Breach b;
      b.type = "OUT_OF_BOUNDS";
      b.severity = "MEDIUM";
      b.status = "EXPOSED";
      b.candidateId = "P" + std::to_string(pageIdx) + "_OOB";
      b.page = pageIdx;
      b.bbox = span.bbox;
      b.recoveredText = span.text;
      b.justification =
          "Texto localizado fora da area de corte visivel (CropBox).";
      findings.push_back(b);
    }
  }
  return findings;
}

// ========================================================================
// FORENSIC REPORT (Plain Text .txt)
// ========================================================================
std::string generateForensicReport(const EvidenceRecord &ev,
                                   const std::vector<Breach> &breaches,
                                   const std::string &outputDir) {
  fs::create_directories(outputDir);
  std::string rid =
      "RPT-" + ev.evidenceId + "-" + getTimestampUTC().substr(0, 10);
  std::string fp = (fs::path(outputDir) / (rid + ".txt")).string();
  std::ofstream f(fp);

  // Separator line
  std::string sep(72, '=');
  std::string sep2(72, '-');

  f << sep << "\n";
  f << "  RELATORIO FORENSE — RedactBreaker v1.0 (C++ Native Engine)\n";
  f << sep << "\n\n";

  // Report header
  f << "  CABECALHO DO RELATORIO\n";
  f << sep2 << "\n";
  f << "  Report ID       : " << rid << "\n";
  f << "  Gerado em (UTC) : " << getTimestampUTC() << "\n";
  f << "  Ferramenta      : RedactBreaker C++ v1.0\n";
  f << "  Classificacao   : USO FORENSE INTERNO\n";
  f << "\n";

  // Evidence metadata
  f << "  METADADOS DA EVIDENCIA\n";
  f << sep2 << "\n";
  f << "  Evidence ID     : " << ev.evidenceId << "\n";
  f << "  Arquivo         : " << ev.fileName << "\n";
  f << "  Caminho Original: " << ev.filePath << "\n";
  f << "  Tamanho (bytes) : " << ev.fileSize << "\n";
  f << "  SHA-256         : " << ev.sha256 << "\n";
  f << "  Integridade     : " << ev.integrityStatus << "\n";
  f << "\n";

  // Analysis summary
  f << "  RESUMO DA ANALISE\n";
  f << sep2 << "\n";
  f << "  Vulnerabilidades: " << breaches.size() << "\n";
  f << "  Status          : "
    << (breaches.empty() ? "LIMPO — Nenhuma vulnerabilidade encontrada"
                         : "VULNERABILIDADES ENCONTRADAS")
    << "\n";
  f << "\n";

  if (!breaches.empty()) {
    f << "  ACHADOS DETALHADOS\n";
    f << sep2 << "\n\n";

    // Count severities
    int critical = 0, high = 0, medium = 0, low = 0;
    for (auto &b : breaches) {
      if (b.severity == "CRITICAL")
        critical++;
      else if (b.severity == "HIGH")
        high++;
      else if (b.severity == "MEDIUM")
        medium++;
      else
        low++;
    }

    f << "  [SEVERIDADE]  CRITICAL: " << critical << "  |  HIGH: " << high
      << "  |  MEDIUM: " << medium << "  |  LOW: " << low << "\n\n";

    for (size_t i = 0; i < breaches.size(); i++) {
      auto &b = breaches[i];
      f << "  ACHADO #" << (i + 1) << "\n";
      f << "  " << std::string(40, '.') << "\n";
      f << "  Tipo           : " << b.type << "\n";
      f << "  Severidade     : " << b.severity << "\n";
      f << "  Status         : " << b.status << "\n";
      f << "  Pagina         : "
        << (b.page >= 0 ? std::to_string(b.page + 1) : "N/A") << "\n";
      f << "  Candidate ID   : " << b.candidateId << "\n";
      f << "  Texto Recuperado:\n";
      f << "    >> " << b.recoveredText << "\n";
      f << "  Justificativa  :\n";
      f << "    " << b.justification << "\n";
      f << "\n";
    }
  }

  f << sep << "\n";
  f << "  FIM DO RELATORIO | " << rid << "\n";
  f << "  AVISO: Este documento contem informacoes sensiveis.\n";
  f << "  Manuseie de acordo com as politicas de cadeia de custodia.\n";
  f << sep << "\n";

  f.close();
  return fp;
}

// ========================================================================
// FULL FORENSIC PIPELINE
// ========================================================================
void runFullAnalysis(const std::string &pdfPath, const std::string &outputDir) {
  std::cout << "\x1b[1;36m[*] Iniciando Pipeline Forense...\x1b[0m\n";
  EvidenceRecord evidence;
  try {
    evidence = ingestFile(pdfPath);
    std::cout << "\x1b[1;32m[+] Arquivo Ingerido | Hash: "
              << evidence.evidenceId << "\x1b[0m\n";
  } catch (std::exception &e) {
    std::cout << "\x1b[1;31m[!] Erro: " << e.what() << "\x1b[0m\n";
    return;
  }
  std::cout << "\x1b[1;36m[*] Decompondo estrutura vetorial do PDF...\x1b[0m\n";
  PDFParser parser;
  if (!parser.loadFile(pdfPath)) {
    std::cout << "\x1b[1;31m[!] Falha no Parsing PDF.\x1b[0m\n";
    return;
  }
  std::cout << "\x1b[1;32m[+] PDF carregado: " << parser.pageCount
            << " pagina(s)\x1b[0m\n";
  auto meta = parser.getMetadata();
  for (auto &t : meta.suspiciousTags)
    std::cout << "\x1b[1;33m[!] ALERTA METADADOS: " << t << "\x1b[0m\n";
  for (auto &[k, v] : meta.standard)
    if (!v.empty())
      std::cout << "    [META] " << k << ": " << v << "\n";
  std::vector<Breach> totalBreaches;
  // Add metadata alerts as findings
  for (auto &t : meta.suspiciousTags) {
    Breach b;
    b.type = "SUSPICIOUS_METADATA";
    b.severity = "LOW";
    b.status = "ALERT";
    b.candidateId = "META";
    b.page = -1;
    b.recoveredText = t;
    b.justification = "Metadados indicam uso de software de edicao grafica, "
                      "sugerindo possivel manipulacao visual do documento.";
    totalBreaches.push_back(b);
  }
  std::cout << "\x1b[1;36m[*] Analisando " << parser.pageCount
            << " paginas...\x1b[0m\n";
  for (int p = 0; p < parser.pageCount; p++) {
    auto cands = findAllCandidates(parser, p);
    if (!cands.empty())
      std::cout << "\x1b[1;33m    [!] Pag " << (p + 1) << ": " << cands.size()
                << " objeto(s) suspeito(s).\x1b[0m\n";
    auto pb = breakRedactions(parser, p, cands);
    for (auto &b : scanInvisibleText(parser, p)) {
      pb.push_back(b);
      std::cout << "\x1b[1;31m    [!] Pag " << (p + 1) << ": INVISIBLE TEXT: '"
                << b.recoveredText.substr(0, 20) << "...'\x1b[0m\n";
    }
    for (auto &b : scanOutOfBounds(parser, p)) {
      pb.push_back(b);
      std::cout << "\x1b[1;31m    [!] Pag " << (p + 1) << ": OUT-OF-BOUNDS: '"
                << b.recoveredText.substr(0, 20) << "...'\x1b[0m\n";
    }
    if (!pb.empty()) {
      std::cout << "\x1b[1;31;1m    [X] QUEBRA CONFIRMADA NA PAG " << (p + 1)
                << "!\x1b[0m\n";
      for (auto &b : pb)
        std::cout << "\x1b[1;31m        -> Exposto: '"
                  << b.recoveredText.substr(0, 40) << "...'\x1b[0m\n";
      totalBreaches.insert(totalBreaches.end(), pb.begin(), pb.end());
    } else if (!cands.empty())
      std::cout << "\x1b[1;32m    [v] Pag " << (p + 1)
                << ": Tarjas seguras.\x1b[0m\n";
  }
  std::cout << "\x1b[1;36m[*] Gerando Relatorio...\x1b[0m\n";
  std::string rp = generateForensicReport(evidence, totalBreaches, outputDir);
  std::cout << "\x1b[1;32;1m\n[+] ANALISE CONCLUIDA.\x1b[0m\n    Relatorio: "
            << rp << "\n";
  if (!totalBreaches.empty())
    std::cout << "\x1b[1;35m\n[SUMMARY] Redactions Quebrados: "
              << totalBreaches.size() << "\x1b[0m\n";
  else
    std::cout
        << "\x1b[1;32m\n[SUMMARY] Nenhuma vulnerabilidade detectada.\x1b[0m\n";
}

void runQuickScan(const std::string &pdfPath) {
  std::cout << "\x1b[1;36m[*] Analise Rapida...\x1b[0m\n";
  PDFParser parser;
  if (!parser.loadFile(pdfPath)) {
    std::cout << "\x1b[1;31m[!] Falha.\x1b[0m\n";
    return;
  }
  auto meta = parser.getMetadata();
  std::cout << "\n\x1b[1;37m--- METADADOS ---\x1b[0m\n";
  for (auto &[k, v] : meta.standard)
    if (!v.empty())
      std::cout << "  " << k << ": " << v << "\n";
  for (auto &t : meta.suspiciousTags)
    std::cout << "  \x1b[1;33m[!] " << t << "\x1b[0m\n";
  std::cout << "\n\x1b[1;37m--- TEXTO ---\x1b[0m\n";
  for (int p = 0; p < parser.pageCount; p++) {
    auto spans = parser.extractTextFromPage(p);
    if (!spans.empty()) {
      std::cout << "\x1b[1;36m  [Pagina " << (p + 1) << "]\x1b[0m\n";
      for (auto &s : spans)
        std::cout << "    " << s.text << "\n";
    }
  }
  std::cout << "\x1b[1;32m[+] Concluido.\x1b[0m\n";
}

void runIntegrityCheck(const std::string &filePath) {
  std::cout << "\x1b[1;36m[*] Verificacao de Integridade...\x1b[0m\n";
  try {
    auto ev = ingestFile(filePath);
    std::cout << "[+] Arquivo:  " << ev.fileName
              << "\n[+] Tamanho:  " << ev.fileSize << " bytes\n";
    std::cout << "[+] SHA-256:  " << ev.sha256
              << "\n[+] Short ID: " << ev.evidenceId << "\n";
    PDFParser parser;
    if (parser.loadFile(filePath))
      std::cout << "[+] Estrutura: \x1b[1;32mPDF VALIDO (" << parser.pageCount
                << " pags, " << parser.xrefTable.size() << " objs)\x1b[0m\n";
    else
      std::cout << "[!] Estrutura: \x1b[1;31mINVALIDO\x1b[0m\n";
  } catch (std::exception &e) {
    std::cout << "\x1b[1;31m[!] " << e.what() << "\x1b[0m\n";
  }
}

// ========================================================================
// SELF-TEST
// ========================================================================
void runSelfTest() {
  std::cout << "\n\x1b[1;36m==================================================="
               "=========\x1b[0m\n";
  std::cout << "\x1b[1;37m  AUTO-TESTE FORENSE (RedactBreaker v1.0)\x1b[0m\n";
  std::cout << "\x1b[1;36m====================================================="
               "=======\x1b[0m\n\n";
  int pass = 0, fail = 0;
  auto test = [&](const std::string &name, bool ok) {
    if (ok) {
      std::cout << "\x1b[1;32m  [PASS] " << name << "\x1b[0m\n";
      pass++;
    } else {
      std::cout << "\x1b[1;31m  [FAIL] " << name << "\x1b[0m\n";
      fail++;
    }
  };
  test("SHA-256 Generation",
       picosha2::hash256_hex_string(std::string("test")).size() == 64);
  {
    unsigned char c[] = {0x78, 0x9C, 0xF3, 0x48, 0xCD, 0xC9, 0xC9,
                         0x07, 0x00, 0x06, 0x2C, 0x02, 0x15};
    std::vector<unsigned char> o;
    bool ok = tinflate::inflate(c, sizeof(c), o);
    test("FlateDecode Inflate",
         ok && std::string(o.begin(), o.end()) == "Hello");
  }
  {
    Rect a = {10, 10, 100, 50}, b = {50, 20, 150, 40};
    auto i = a.intersect(b);
    test("BBox Intersection",
         i.x0 == 50 && i.y0 == 20 && i.x1 == 100 && i.y1 == 40);
  }
  {
    int w = 100, h = 100;
    std::vector<unsigned char> g(w * h, 255);
    for (int y = 20; y < 50; y++)
      for (int x = 20; x < 80; x++)
        g[y * w + x] = 0;
    test("Raster Detection",
         RasterAnalysis::findBlackRects(g.data(), w, h, 1.0).size() == 1);
  }
  test("JSON Escaping", escapeJSON("a\"b\nc") == "a\\\"b\\nc");
  test("Suspicious Creator",
       toLower("Adobe Photoshop").find("photoshop") != std::string::npos);
  test("Timestamp UTC", !getTimestampUTC().empty());
  test("Trim Whitespace", trim("  hello  ") == "hello");
  std::cout << "\n\x1b[1;36m==================================================="
               "=========\x1b[0m\n";
  std::cout << "  \x1b[1;37mRESULTADOS: \x1b[1;32m" << pass
            << " PASS \x1b[1;30m| \x1b[1;31m" << fail << " FAIL\x1b[0m\n";
  std::cout << "\x1b[1;36m====================================================="
               "=======\x1b[0m\n";
  if (!fail)
    std::cout
        << "\n\x1b[1;42;30m   SISTEMA INTEGRALMENTE OPERACIONAL   \x1b[0m\n";
  else
    std::cout << "\n\x1b[1;41;37m   FALHA EM " << fail
              << " MODULO(S)   \x1b[0m\n";
}

// ========================================================================
// MAIN
// ========================================================================
int main() {
  enableANSI();
  std::cout
      << "\n\x1b[1;33m[*] Inicializando RedactBreaker Engine v1.0...\x1b[0m\n";
  sleepMs(300);
  std::cout << "[+] Motor de Analise PDF Carregado\n[+] Inflate (FlateDecode) "
               "Inicializado\n";
  std::cout << "[+] GDI+ Raster Engine Disponivel\n[+] SHA-256 Engine Ativo\n";
  sleepMs(200);
  std::cout << "\x1b[1;32m[+] SISTEMA PRONTO.\x1b[0m\n\nPressione ENTER para "
               "carregar...";
  std::cin.get();
  int choice;
  do {
#ifdef _WIN32
    std::system("cls");
#else
    std::system("clear");
#endif
    exibirDesenho();
    std::cout << "SENTINEL DATA SOLUTIONS | ENGINE: \x1b[1;36mv1.0-FORENSIC "
                 "[C++ NATIVE]\x1b[0m\n";
    std::cout << "\n\x1b[1;37m=== SISTEMA DE ANALISE FORENSE DE REDACTIONS "
                 "===\x1b[0m\n";
    std::cout << "------------------------------------------------\n";
    std::cout << "1. Analisar PDF (Pipeline Forense Completo)\n";
    std::cout << "2. Analise Rapida (Metadados + Texto)\n";
    std::cout << "3. Verificar Integridade (SHA-256 + Estrutura)\n";
    std::cout << "4. Executar Auto-Teste (Validacao de Modulos)\n";
    std::cout << "5. Sobre / Ajuda\n";
    std::cout << "0. Sair\n";
    std::cout << "------------------------------------------------\nEscolha: ";
    if (!(std::cin >> choice)) {
      std::cin.clear();
      std::cin.ignore(10000, '\n');
      choice = -1;
    }
    if (choice == 0)
      break;
    if (choice == 4) {
      runSelfTest();
      std::cout << "\n\x1b[1;33mENTER para voltar...\x1b[0m";
      std::cin.ignore(10000, '\n');
      std::cin.get();
      continue;
    }
    if (choice == 5) {
      std::cout
          << "\n\x1b[1;37m=== REDACTBREAKER v1.0 (C++ EDITION) ===\x1b[0m\n";
      std::cout << "\nFerramenta forense para analise de falhas de redaction "
                   "em PDFs.\n";
      std::cout << "Detecta texto oculto sob tarjas, texto invisivel, conteudo "
                   "fora dos limites,\n";
      std::cout
          << "e tarjas em imagens escaneadas.\n\n\x1b[1;33mMODULOS:\x1b[0m\n";
      std::cout << "  [1] Ingestao Forense (SHA-256)\n  [2] Parser PDF Raw "
                   "(Xref/Streams/FlateDecode)\n";
      std::cout << "  [3] Finder Vetorial\n  [4] Finder Raster (GDI+)\n  [5] "
                   "Breaker (BBox Intersection)\n";
      std::cout
          << "  [6] Deep Forensics (Invisible/OOB)\n  [7] Reporter (JSON)\n";
      std::cout << "\n\x1b[1;31m[!] USO EXCLUSIVAMENTE DIDATICO\x1b[0m\nENTER "
                   "para voltar...";
      std::cin.ignore(10000, '\n');
      std::cin.get();
      continue;
    }
    if (choice >= 1 && choice <= 3) {
      std::string fp;
      std::cout << "\nCaminho do PDF: ";
      std::cin.ignore(10000, '\n');
      std::getline(std::cin, fp);
      if (fp.size() >= 2 && fp.front() == '"' && fp.back() == '"')
        fp = fp.substr(1, fp.size() - 2);
      if (!fs::exists(fp)) {
        std::cout << "\x1b[1;31m[!] Nao encontrado.\x1b[0m\nENTER...";
        std::cin.get();
        continue;
      }
      if (choice == 1) {
        std::string od;
        std::cout << "Diretorio saida (ENTER=./data/output): ";
        std::getline(std::cin, od);
        if (od.empty())
          od = "./data/output";
        runFullAnalysis(fp, od);
      } else if (choice == 2)
        runQuickScan(fp);
      else
        runIntegrityCheck(fp);
      std::cout << "\n\x1b[1;33mENTER para voltar...\x1b[0m";
      std::cin.get();
      continue;
    }
    std::cout << "\n[!] Opcao invalida!\n";
    std::cin.ignore(10000, '\n');
    std::cin.get();
  } while (choice != 0);
  std::cout << "\n\x1b[1;36m[*] RedactBreaker encerrado.\x1b[0m\n";
  return 0;
}
