using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Collectors;

public class WindowsSystemInfoCollector
{
    public (string Hostname, string IpAddress, string OsVersion, string OsBuild) Collect()
    {
        string hostname = Environment.MachineName;
        string osVersion = "Windows";
        string osBuild = "Unknown Build";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                string productName = key.GetValue("ProductName")?.ToString() ?? "Windows";
                string displayVersion = key.GetValue("DisplayVersion")?.ToString() ?? "";
                string currentBuildStr = key.GetValue("CurrentBuild")?.ToString() ?? "0";
                string ubr = key.GetValue("UBR")?.ToString() ?? "0";

                // راه‌حل قطعی: بررسی Build Number به جای نام
                // ویندوز ۱۱ از بیلد 22000 شروع می‌شود. اگر بالاتر بود و نامش ۱۰ بود، یعنی مایکروسافت اشتباه کرده!
                if (int.TryParse(currentBuildStr, out int currentBuildNum))
                {
                    if (currentBuildNum >= 22000 && productName.Contains("Windows 10"))
                    {
                        productName = productName.Replace("Windows 10", "Windows 11");
                    }
                }

                osVersion = productName;
                osBuild = $"Version {displayVersion} (OS Build {currentBuildStr}.{ubr})";
            }
        }
        catch { }

        string ipAddress = "N/A";
        try
        {
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in networkInterfaces)
            {
                if (ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var ipProps = ni.GetIPProperties();
                    var ipv4 = ipProps.UnicastAddresses.FirstOrDefault(ua =>
                        ua.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (ipv4 != null)
                    {
                        ipAddress = ipv4.Address.ToString();
                        break;
                    }
                }
            }
        }
        catch { }

        return (hostname, ipAddress, osVersion, osBuild);
    }
}