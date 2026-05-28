import AdmZip from 'adm-zip';

const ALLOWED_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.env',
  '.yml', '.yaml', '.json', '.config', '.xml', '.rb', '.php', '.go', '.rs'
];

const SKIP_PATHS = [
  'node_modules/', 'dist/', 'build/', '.git/', 'vendor/',
  '__pycache__/', '.next/', 'coverage/'
];

const MAX_FILES = 80;

/**
 * Check if a file should be included based on extension and path
 * @param {string} path - File path
 * @returns {boolean}
 */
function shouldIncludeFile(path) {
  // Check if path contains any skip patterns
  for (const skipPath of SKIP_PATHS) {
    if (path.includes(skipPath)) {
      return false;
    }
  }
  
  // Check if file has allowed extension
  const hasAllowedExtension = ALLOWED_EXTENSIONS.some(ext => path.endsWith(ext));
  return hasAllowedExtension;
}

/**
 * Parse a ZIP buffer and extract code files
 * @param {Buffer} buffer - ZIP file buffer
 * @returns {string} - Concatenated codebase text
 */
export function parseZip(buffer) {
  const zip = new AdmZip(buffer);
  const entries = zip.getEntries();
  
  // Filter and limit entries
  const validEntries = entries
    .filter(entry => !entry.isDirectory && shouldIncludeFile(entry.entryName))
    .slice(0, MAX_FILES);
  
  if (validEntries.length === 0) {
    throw new Error('No supported files found in ZIP archive');
  }
  
  // Read and concatenate file contents
  const files = validEntries.map(entry => {
    try {
      const content = entry.getData().toString('utf8');
      return { path: entry.entryName, content };
    } catch (error) {
      // Skip files that can't be read
      return null;
    }
  }).filter(f => f !== null);
  
  // Concatenate into single text block (same format as githubFetcher)
  const codebaseText = files
    .map(file => `=== FILE: ${file.path} ===\n${file.content}`)
    .join('\n\n');
  
  return codebaseText;
}
