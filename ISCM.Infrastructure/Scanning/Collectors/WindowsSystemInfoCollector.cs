using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace ISCM.Infrastructure.Scanning.Collectors;

public class WindowsSystemInfoCollector
{
    public (string Hostname, string IpAddress, string OsVersion) Collect()
    {
        // 1. دریافت نام سیستم (Computer Name)
        string hostname = Environment.MachineName;

        // 2. دریافت نسخه ویندوز
        string osVersion = RuntimeInformation.OSDescription;

        // 3. دریافت آدرس IP (جستجو در کارت‌های شبکه)
        string ipAddress = "N/A";
        try
        {
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (var ni in networkInterfaces)
            {
                // فقط کارت‌های شبکه‌ای که روشن و فعال هستند
                if (ni.OperationalStatus == OperationalStatus.Up &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                {
                    var ipProps = ni.GetIPProperties();
                    var ipv4 = ipProps.UnicastAddresses.FirstOrDefault(ua =>
                        ua.Address.AddressFamily == AddressFamily.InterNetwork);

                    if (ipv4 != null)
                    {
                        ipAddress = ipv4.Address.ToString();
                        break; // اولین IP مناسب را پیدا کردیم، از حلقه خارج می‌شویم
                    }
                }
            }
        }
        catch
        {
            // اگر به هر دلیلی IP خوانده نشد، همان N/A می‌ماند و برنامه کرش نمی‌کند
        }

        return (hostname, ipAddress, osVersion);
    }
}
