using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ISCM.Infrastructure.Scanning.Collectors;

public class WindowsSystemInfoCollector
{
    public (string Hostname, string IpAddress, string OsName, string OsBuild) Collect()
    {
        string hostname = Environment.MachineName;

        string osName = "Unknown OS";
        string osBuild = "Unknown Build";

        try
        {
            // خواندن نام و نسخه ویندوز دقیقاً مثل winver از رجیستری
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                string productName = key.GetValue("ProductName")?.ToString() ?? "Windows";
                string editionId = key.GetValue("EditionID")?.ToString() ?? "";
                string displayVersion = key.GetValue("DisplayVersion")?.ToString() ?? "";
                string currentBuild = key.GetValue("CurrentBuild")?.ToString() ?? "";
                object ubrObj = key.GetValue("UBR") ?? 0;
                string ubr = ubrObj.ToString();

                osName = $"{productName}"; // مثال: Windows 11 IoT Enterprise LTSC
                osBuild = $"{displayVersion} (OS Build {currentBuild}.{ubr})"; // مثال: 24H2 (OS Build 26100.8894)
            }
        }
        catch { }

        string ipAddress = "N/A";
        try
        {
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in networkInterfaces)
            {
                if (ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var ipProps = ni.GetIPProperties();
                    var ipv4 = ipProps.UnicastAddresses.FirstOrDefault(ua => ua.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (ipv4 != null)
                    {
                        ipAddress = ipv4.Address.ToString();
                        break;
                    }
                }
            }
        }
        catch { }

        return (hostname, ipAddress, osName, osBuild);
    }
}