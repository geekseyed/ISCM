using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Collectors;

public class WindowsSystemInfoCollector
{
    // خروجی تبدیل به ۵ آیتم شد (شامل MacAddress)
    public (string Hostname, string IpAddress, string MacAddress, string OsVersion, string OsBuild) Collect()
    {
        string hostname = Environment.MachineName;
        string osVersion = "Windows";
        string osBuild = "Unknown Build";
        string ipAddress = "N/A";
        string macAddress = "N/A";

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                string productName = key.GetValue("ProductName")?.ToString() ?? "Windows";
                string displayVersion = key.GetValue("DisplayVersion")?.ToString() ?? "";
                string currentBuildStr = key.GetValue("CurrentBuild")?.ToString() ?? "0";
                string ubr = key.GetValue("UBR")?.ToString() ?? "0";

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
                        // خواندن MAC آدرس و فرمت کردن آن (XX-XX-XX-XX-XX-XX)
                        macAddress = string.Join("-", ni.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
                        break;
                    }
                }
            }
        }
        catch { }

        return (hostname, ipAddress, macAddress, osVersion, osBuild);
    }
}