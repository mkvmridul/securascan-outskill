/**
 * Fetch repository contents from GitHub
 */

const ALLOWED_EXTENSIONS = [
  '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.env',
  '.yml', '.yaml', '.json', '.config', '.xml', '.rb', '.php', '.go', '.rs'
];

const SKIP_PATHS = [
  'node_modules/', 'dist/', 'build/', '.git/', 'vendor/',
  '__pycache__/', '.next/', 'coverage/'
];

const MAX_FILES = 80;
const BATCH_SIZE = 10;

/**
 * Parse owner and repo from GitHub URL
 * @param {string} repoUrl - GitHub repository URL
 * @returns {{owner: string, repo: string}}
 */
function parseGitHubUrl(repoUrl) {
  // Handle various GitHub URL formats:
  // https://github.com/owner/repo
  // https://github.com/owner/repo.git
  // https://github.com/owner/repo/tree/branch
  // git@github.com:owner/repo.git
  
  const httpsMatch = repoUrl.match(/github\.com\/([^\/]+)\/([^\/\.]+)/);
  if (httpsMatch) {
    return { owner: httpsMatch[1], repo: httpsMatch[2] };
  }
  
  const sshMatch = repoUrl.match(/git@github\.com:([^\/]+)\/([^\.]+)/);
  if (sshMatch) {
    return { owner: sshMatch[1], repo: sshMatch[2] };
  }
  
  throw new Error('Invalid GitHub URL format');
}

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
 * Fetch file contents in batches
 * @param {string} owner - Repository owner
 * @param {string} repo - Repository name
 * @param {string[]} paths - Array of file paths
 * @returns {Promise<Array<{path: string, content: string}>>}
 */
async function fetchFilesInBatches(owner, repo, paths) {
  const results = [];
  
  for (let i = 0; i < paths.length; i += BATCH_SIZE) {
    const batch = paths.slice(i, i + BATCH_SIZE);
    
    const batchPromises = batch.map(async (path) => {
      try {
        const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}`;
        const response = await fetch(url, {
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SecuraScan'
          }
        });
        
        if (!response.ok) {
          return null;
        }
        
        const data = await response.json();
        
        if (data.content && data.encoding === 'base64') {
          const content = Buffer.from(data.content, 'base64').toString('utf8');
          return { path, content };
        }
        
        return null;
      } catch (error) {
        // Silently skip failed files
        return null;
      }
    });
    
    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults.filter(r => r !== null));
  }
  
  return results;
}

/**
 * Fetch and parse a GitHub repository
 * @param {string} repoUrl - GitHub repository URL
 * @returns {Promise<string>} - Concatenated codebase text
 */
export async function fetchGithubRepo(repoUrl) {
  const { owner, repo } = parseGitHubUrl(repoUrl);
  
  // Fetch the repository tree
  const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`;
  const treeResponse = await fetch(treeUrl, {
    headers: {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'SecuraScan'
    }
  });
  
  if (!treeResponse.ok) {
    const errorData = await treeResponse.json().catch(() => ({}));
    throw new Error(`Failed to fetch repository tree: ${treeResponse.status} ${errorData.message || ''}`);
  }
  
  const treeData = await treeResponse.json();
  
  // Filter files by extension and path, cap at MAX_FILES
  const filePaths = treeData.tree
    .filter(item => item.type === 'blob' && shouldIncludeFile(item.path))
    .map(item => item.path)
    .slice(0, MAX_FILES);
  
  if (filePaths.length === 0) {
    throw new Error('No supported files found in repository');
  }
  
  // Fetch file contents in batches
  const files = await fetchFilesInBatches(owner, repo, filePaths);
  
  // Concatenate into single text block
  const codebaseText = files
    .map(file => `=== FILE: ${file.path} ===\n${file.content}`)
    .join('\n\n');
  
  return codebaseText;
}
