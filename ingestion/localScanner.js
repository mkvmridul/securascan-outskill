import { readdirSync, readFileSync, statSync } from 'fs';
import { join, extname } from 'path';

const ALLOWED_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.env',
  '.yml', '.yaml', '.json', '.config', '.xml', '.rb', '.php', '.go', '.rs'
];

const SKIP_DIRS = [
  'node_modules', 'dist', 'build', '.git', 'vendor',
  '__pycache__', '.next', 'coverage', '.venv', 'venv',
  '.idea', '.vscode', 'target', 'out', '.cache'
];

const MAX_FILES = 40;  // Reduced from 80
const MAX_FILE_SIZE = 50 * 1024;  // 50KB per file (reduced from 100KB)
const MAX_TOTAL_SIZE = 150 * 1024;  // 150KB total codebase limit

/**
 * Check if a file should be included based on extension
 * @param {string} filename - File name
 * @returns {boolean}
 */
function shouldIncludeFile(filename) {
  const ext = extname(filename).toLowerCase();
  return ALLOWED_EXTENSIONS.includes(ext);
}

/**
 * Check if a directory should be skipped
 * @param {string} dirname - Directory name
 * @returns {boolean}
 */
function shouldSkipDir(dirname) {
  return SKIP_DIRS.includes(dirname) || dirname.startsWith('.');
}

/**
 * Recursively scan a directory for code files
 * @param {string} dirPath - Directory path
 * @param {string} basePath - Base path for relative paths
 * @param {Array} files - Accumulated files array
 * @returns {Array} - Array of {path, content} objects
 */
function scanDirectory(dirPath, basePath = '', files = []) {
  if (files.length >= MAX_FILES) {
    return files;
  }
  
  const entries = readdirSync(dirPath, { withFileTypes: true });
  
  for (const entry of entries) {
    if (files.length >= MAX_FILES) break;
    
    const fullPath = join(dirPath, entry.name);
    const relativePath = basePath ? join(basePath, entry.name) : entry.name;
    
    if (entry.isDirectory()) {
      if (!shouldSkipDir(entry.name)) {
        scanDirectory(fullPath, relativePath, files);
      }
    } else if (entry.isFile() && shouldIncludeFile(entry.name)) {
      try {
        const stat = statSync(fullPath);
        // Skip files larger than MAX_FILE_SIZE
        if (stat.size <= MAX_FILE_SIZE) {
          const content = readFileSync(fullPath, 'utf8');
          files.push({ path: relativePath, content, size: stat.size });
        }
      } catch (error) {
        // Skip files that can't be read
      }
    }
  }
  
  return files;
}

/**
 * Truncate file content to keep only security-relevant parts
 */
function truncateContent(content, maxLines = 200) {
  const lines = content.split('\n');
  if (lines.length <= maxLines) return content;
  
  // Keep first 100 and last 100 lines (where most security issues are)
  const first = lines.slice(0, 100).join('\n');
  const last = lines.slice(-100).join('\n');
  return `${first}\n\n/* ... ${lines.length - 200} lines truncated ... */\n\n${last}`;
}

/**
 * Scan a local directory and return concatenated codebase text
 * @param {string} dirPath - Directory path to scan
 * @returns {Promise<string>} - Concatenated codebase text
 */
export async function scanLocalDirectory(dirPath) {
  let files = scanDirectory(dirPath);
  
  if (files.length === 0) {
    throw new Error('No supported files found in directory');
  }
  
  // Sort by size (smaller first) and prioritize security-relevant files
  const priorityFiles = ['.env', 'config', 'auth', 'login', 'password', 'secret', 'api', 'db', 'database'];
  files.sort((a, b) => {
    const aPriority = priorityFiles.some(p => a.path.toLowerCase().includes(p)) ? 0 : 1;
    const bPriority = priorityFiles.some(p => b.path.toLowerCase().includes(p)) ? 0 : 1;
    if (aPriority !== bPriority) return aPriority - bPriority;
    return a.size - b.size;
  });
  
  // Limit total size
  let totalSize = 0;
  const selectedFiles = [];
  for (const file of files) {
    if (totalSize + file.size > MAX_TOTAL_SIZE) break;
    selectedFiles.push(file);
    totalSize += file.size;
  }
  
  console.log(`\x1b[90m   Selected ${selectedFiles.length}/${files.length} files (${(totalSize/1024).toFixed(1)}KB)\x1b[0m`);
  
  // Concatenate with truncation
  const codebaseText = selectedFiles
    .map(file => `=== FILE: ${file.path} ===\n${truncateContent(file.content)}`)
    .join('\n\n');
  
  return codebaseText;
}
