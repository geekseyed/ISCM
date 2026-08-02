using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;

namespace ISCM.Domain.ValueObjects;

public class IPAddressValue
{
    public string Value { get; private set; }

    private IPAddressValue()
    {
        Value = string.Empty;
    }


    public IPAddressValue(string value)
    {
        if (!IPAddress.TryParse(value, out _))
        {
            throw new ArgumentException("Invalid IP Address");
        }

        Value = value;
    }


    public override string ToString()
    {
        return Value;
    }
}