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
                string currentBuild = key.GetValue("CurrentBuild")?.ToString() ?? "0";
                string ubr = key.GetValue("UBR")?.ToString() ?? "0";

                // اصلاح تنبلی مایکروسافت: اگر نسخه اصلی ۱۱ بود، نام را به ۱۱ تغییر بده
                if (int.TryParse(key.GetValue("CurrentMajorVersionNumber")?.ToString(), out int majorVersion))
                {
                    if (majorVersion >= 11 && productName.Contains("Windows 10"))
                    {
                        productName = productName.Replace("Windows 10", "Windows 11");
                    }
                }

                osVersion = productName;
                osBuild = $"Version {displayVersion} (OS Build {currentBuild}.{ubr})";
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