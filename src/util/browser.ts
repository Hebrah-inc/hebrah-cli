// System default browser launcher for macOS, Windows, and Linux.
import { exec } from 'node:child_process';
import { platform } from 'node:os';

/**
 * Launch the user's default browser to open the given URL.
 * Returns true if the command was dispatched without error, false otherwise.
 */
export function openBrowser(url: string): Promise<boolean> {
  return new Promise((resolve) => {
    let cmd: string;
    const osPlatform = platform();

    if (osPlatform === 'darwin') {
      cmd = `open "${url.replace(/"/g, '\\"')}"`;
    } else if (osPlatform === 'win32') {
      cmd = `start "" "${url.replace(/"/g, '^"')}"`;
    } else {
      cmd = `xdg-open "${url.replace(/"/g, '\\"')}"`;
    }

    exec(cmd, (err) => {
      if (err) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}
