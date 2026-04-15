"""Detect connected iOS devices via Windows Portable Devices API (no external deps)"""
import ctypes
from ctypes import wintypes

class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                 ("Data2", wintypes.WORD),
                 ("Data3", wintypes.WORD),
                 ("Data4", wintypes.BYTE * 8)]

class PROPERTYKEY(ctypes.Structure):
    _fields_ = [("fmtid", GUID), ("pid", wintypes.DWORD)]

# PKEY_Device_InstanceId = {A45C254E-DF1C-4EFD-8020-67D146A850E0}, 2
PKEY_Device_InstanceId = PROPERTYKEY(GUID(0xa45c254e, 0xdf1c, 0x4efd, 0x8020, (0x67,0xd1,0x46,0xa8,0x50,0xe0,0x00,0x00)), 2)
PKEY_FirmwareVersion = PROPERTYKEY(GUID(0xa45c254e, 0xdf1c, 0x4efd, 0x8020, (0x67,0xd1,0x46,0xa8,0x50,0xe0,0x00,0x00)), 5)
PKEY_Device_Name = PROPERTYKEY(GUID(0xa45c254e, 0xdf1c, 0x4efd, 0x8020, (0x67,0xd1,0x46,0xa8,0x50,0xe0,0x00,0x00)), 3)

# COM Interfaces (IID declarations)
IID_IPortableDeviceManager = GUID(0xa156e9a4, 0xed46, 0x474a, 0x9a, (0x7c,0x75,0x94,0x33,0x41,0x90,0x1e,0x3b))
IID_IPortableDeviceResources = GUID(0x2c00f100, 0x9848, 0x4b4c, 0xad, (0x46,0x2c,0x8c,0xa3,0x68,0x4e,0x47,0x0d))
IID_IPropertyStore = GUID(0x886d8eeb, 0x8cf2, 0x4446, 0x8d, (0x02,0xd8,0x0e,0xc8,0x3f,0xee,0xf2,0x97))

CLSID_PortableDeviceManager = GUID(0x1ee7c931, 0xef1b, 0x4e4a, 0x99, (0x7f,0xdd,0x88,0x2b,0xf6,0x1f,0x39,0x31))
CLSID_SystemDeviceEnum = GUID(0x62c0eefb, 0x486e, 0x4f7d, 0x95, (0x8c,0x0b,0x8f,0x68,0xbe,0x50,0x4e,0x3d))

COINIT_APARTMENTTHREADED = 2
DEVICE_NOTIFY_WINDOW = 0

def win32_co_init():
    Ole32 = ctypes.windll.ole32
    Ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    return Ole32

def detect_ios_devices_via_pnp():
    """Use SetupAPI to enumerate connected USB devices and find iOS devices."""
    from ctypes import POINTER
    import comtypes
    from comtypes import CoCreateInstance, CLSCTX_ALL

    devices = []
    try:
        # Use SetupAPI to find devices with Apple VID
        SetupDiGetClassDevs = ctypes.windll.setupapi.SetupDiGetClassDevsW
        SetupDiEnumDeviceInfo = ctypes.windll.setupapi.SetupDiEnumDeviceInfo
        SetupDiDestroyDeviceInfoList = ctypes.windll.setupapi.SetupDiDestroyDeviceInfoList
        CM_Get_Device_ID = ctypes.windll.setupapi.CM_Get_Device_IDA
        
        DIGCF_ALLCLASSES = 0x4
        DIGCF_PRESENT = 0x2
        INVALID_HANDLE_VALUE = -1

        class SP_DEVINFO_DATA(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.DWORD),
                        ("ClassGuid", GUID),
                        ("DevInst", wintypes.DWORD),
                        ("Reserved", ctypes.c_void_p)]

        hdevinfo = SetupDiGetClassDevs(None, None, None, DIGCF_ALLCLASSES | DIGCF_PRESENT)
        if hdevinfo == INVALID_HANDLE_VALUE:
            return devices

        try:
            devinfo = SP_DEVINFO_DATA()
            devinfo.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
            i = 0
            while SetupDiEnumDeviceInfo(hdevinfo, i, ctypes.byref(devinfo)):
                i += 1
                # Get device instance ID
                buf_size = 200
                buf = ctypes.create_string_buffer(buf_size)
                CM_Get_Device_ID(devinfo.DevInst, buf, buf_size, 0)
                instance_id = buf.value.decode('utf-8', errors='replace')
                
                # Check if it's an Apple/iOS device
                if any(vid in instance_id.upper() for vid in ['VID_05AC', 'APPLE', 'MOBILEDEVICE']):
                    devices.append({
                        'udid': instance_id.replace('\\', '-').replace('&', '-'),
                        'name': 'iPhone',
                        'instance_id': instance_id
                    })
        finally:
            SetupDiDestroyDeviceInfoList(hdevinfo)
    except Exception as e:
        print(f'PNP detection error: {e}')
    return devices

def detect_ios_devices():
    """Try multiple methods to detect iOS devices."""
    results = detect_ios_devices_via_pnp()
    
    # Also try idevice_id
    import subprocess, os
    LIBIMOBILE = os.path.join(os.path.dirname(__file__), 'libimobiledevice')
    exe = os.path.join(LIBIMOBILE, 'idevice_id.exe')
    if os.path.exists(exe):
        try:
            r = subprocess.run([exe, '-l'], capture_output=True, timeout=10)
            output = r.stdout.decode('utf-8', errors='replace').strip()
            for line in output.split('\n'):
                line = line.strip()
                if line and 'No device' not in line and 'ERROR' not in line:
                    results.append({'udid': line, 'name': 'iPhone', 'source': 'idevice'})
        except:
            pass
    
    # Deduplicate by instance_id
    seen = set()
    unique = []
    for d in results:
        key = d.get('instance_id', d.get('udid', ''))
        if key and key not in seen:
            seen.add(key)
            unique.append(d)
    return unique

if __name__ == '__main__':
    devs = detect_ios_devices()
    print(f'Found {len(devs)} iOS device(s):')
    for d in devs:
        print(f'  {d}')
