/**
 * Finds the line number of a specific pattern in the code.
 * @param code - The entire code as a string.
 * @param pattern - The substring or regex to search for.
 * @returns The line number (0-based index), or -1 if not found.
 */
export function findLineNumber(code: string, pattern: string): number {
    const lines = code.split('\n'); // Split the code into lines
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(pattern)) {
        return i; // Return the line number (0-based index)
      }
    }
    return -1; // Return -1 if the pattern is not found
  }
  