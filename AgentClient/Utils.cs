using log4net;
using log4net.Config;
using System;
using System.Collections;
using System.IO;
using System.IO.Pipelines;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
//for lib loaddll

namespace AgentClient
{

    static class NativeMethods
    {
        [DllImport("kernel32.dll", EntryPoint = "LoadLibrary", SetLastError = true)]
        //public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPWStr)] string dllToLoad);
        public static extern IntPtr LoadLibrary(string dllToLoad);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);
    }

    //[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi,Pack =2)]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct PP_DISPPARM
    {
        public byte offset;
        public byte clear_lines;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 41)]
        public byte[] text;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] reserved;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct PP_PINPARM
    {
        public byte mindigits;         /* min. number of digits */
        public byte maxdigits;         /* max. number of digits */
        public byte offset;            /* start location for PIN display */
        public byte timeout;           /* inter-digit timeout during entry */
        public byte beep;              /* 1 is on */
        public byte keyid;             /* PIN key number, use PPKEY_1, PPKEY_2 etc. */
        public byte format;            /* use PINFMT_ANSI or PINFMT_ISO */
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] PANdata;    /* null terminated PAN string */
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public byte[] reserved;
    };

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct PP_MSR
    {
        public int length1;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] data1;
        public int length2;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
        public byte[] data2;
        public int length3;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 108)]
        public byte[] data3;
    }

    // test
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct KTP_EL
    {
        [MarshalAs(UnmanagedType.LPStr, SizeConst = 80)]
        public string errorCode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
        public char[] hardwareId;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
        public char[] sn;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
        public char[] firmwareVersion;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
        public char[] statusDevice;
    };

    public class Demography
    {
        public string Nik { get; set; }
        public string Name { get; set; }
        public string Address { get; set; }
        public string PlaceOfBirth { get; set; }
        public string DateOfBirth { get; set; }
        public string Gender { get; set; }
        public string RT { get; set; }
        public string RW { get; set; }
        public string Village { get; set; }
        public string SubDistrict { get; set; }
        public string City { get; set; }
        public string Province { get; set; }
        public string BloodType { get; set; }
        public string Religion { get; set; }
        public string MaritalStatus { get; set; }
        public string Occupation { get; set; }
        public string Nationality { get; set; }
        public string PlaceOfIssue { get; set; }
    }

    public class DeviceReply
    {
        int error_code;
        string err_message;

        public int Error_code
        {
            get
            {
                return error_code;
            }

            set
            {
                error_code = value;
            }
        }

        public string Err_message
        {
            get
            {
                return err_message;
            }

            set
            {
                err_message = value;
            }
        }
    }
    class Utils
    {
        string exeDirectory ="./refrences" ;//System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
        private static readonly ILog log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);


        public Utils(string opertion)
        {
            this.InitLibrary(opertion);

        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadOpen(int port);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadDisplay(ref PP_DISPPARM pp_dispparm);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadPoll();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadClose();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadReset();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadMSRRead(byte timeout, ref PP_DISPPARM pp_dispparm, ref PP_MSR pp_msr);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int _PinpadGetPIN(ref PP_DISPPARM pp_dispparm, ref PP_PINPARM pp_pinparm, byte[] data);

        //

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ektp_putKTP(byte[] err, byte[] dispMessage, int timeOut, byte[] fingerType);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl,CharSet=CharSet.Ansi)]
        //public delegate int ektp_getDataDemography(byte[] error, int timeout, byte[] operatorId, byte[] operatorNIK, byte[] authorizatorId, byte[] authorizatorNIK, ref StringBuilder ektpData);
        public delegate int ektp_getDataDemography(byte[] error, int timeout, string operatorId, string operatorNIK, string authorizatorId, string authorizatorNIK, ref IntPtr ektpData);


        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ektp_verifyFinger(byte[] err, byte[] dispMessage, int timeOut, byte[] fingerType, byte[] operatorId, byte[] operatorNik);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ektp_open(byte[] err);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ektp_close(byte[] err);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ektp_info(byte[] err, byte[] hardware, byte[] sn, byte[] firmware, byte[] status);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        public delegate int EKTP_VerifyIsoTemplate(byte[] err, string nip, byte[] isoTemplate, int timeOut, string wsid, int datetime, int count, byte[] hash, byte[] matchScore);
        //

        public IntPtr pDll;


        public int InitLibrary(string operation)
        {
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));

         
            try
            {
                string path ="";
                log.Info("Library Initailitaion");
                if(operation == "2" || operation == "21")
                {
                    path = exeDirectory + "\\EDCTool.dll";
                }
                if (operation == "1" || operation == "12" || operation == "13" || operation == "14" || operation == "15")
                {
                    path = exeDirectory + "\\ektpdll.dll";
                }
                    
                if (System.IO.File.Exists(path))
                {
                    Console.WriteLine("File Exist");
                    log.Info("File Library Exist");
                }
                else
                {
                    Console.WriteLine("File Not Exist");
                    log.Warn("File Library Not Exist");
                }

                this.pDll = NativeMethods.LoadLibrary(path);


                var lstErrCode = Marshal.GetLastWin32Error();

                if (pDll == IntPtr.Zero)
                {
                    log.Warn("Result Code -1, Library Not Exist");
                    return -1;
                }
                else
                {
                    log.Info("Result Code 0, Library Exist");
                    return 0;
                }
                    
            }
            catch(Exception err)
            {
                log.Error(err.Message);
                return -1;
            }
        }

        #region ~ KTP ELECTRONIC DEVICE ~
        public DeviceReply EktpInfo()
        {
            // Load configuration
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));
            DeviceReply device = new DeviceReply();
            int theResult = -2;
            try
            {
                log.Info("Get KTP-EL Info");
                IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_info");

                if (pAddressOfFunctionToCall == IntPtr.Zero)
                {
                    log.Error("Cannot Call ektp_info function");
                    device.Error_code = -1;
                    device.Err_message = "Method Or Function Not Found";
                    return device;
                }

                ektp_info ektpInfo = (ektp_info)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_info));

                try
                {

                    byte[] errorCode = new byte[80];
                    byte[] hardwareId = new byte[50];
                    byte[] sn = new byte[50];
                    byte[] firmwareVersion = new byte[50];
                    byte[] statusDevice = new byte[30];
                    theResult = ektpInfo(errorCode, hardwareId, sn, firmwareVersion, statusDevice);

                    string errCode = System.Text.ASCIIEncoding.ASCII.GetString(errorCode).Replace("\0", "");
                    string har = System.Text.ASCIIEncoding.ASCII.GetString(hardwareId).Replace("\0", "");
                    string s = System.Text.ASCIIEncoding.ASCII.GetString(sn).Replace("\0", "");
                    string firm = System.Text.ASCIIEncoding.ASCII.GetString(firmwareVersion).Replace("\0", "");
                    string statDevice = System.Text.ASCIIEncoding.ASCII.GetString(statusDevice).Replace("\0", "");
                    log.Info("Result Code: "+ theResult);
                    log.Info("Result Message: " + errCode);
                    device.Error_code = theResult;
                    device.Err_message = errCode;
                }
                catch (Exception e) { Console.WriteLine(e.Message); }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }


            return device;
        }

        public DeviceReply DeviceOpen()
        {
            // Load configuration
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));

            DeviceReply device = new DeviceReply();
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_open");
            log.Info("Open KTP-EL Connection");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                log.Error("Cannot Call ektp_open function");
                device.Error_code = -1;
                device.Err_message = "Method Or Function Not Found";
                return device;
            }
            ektp_open ektpOpen = (ektp_open)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_open));

            byte[] e = new byte[80];
            int theResult = ektpOpen(e);
            log.Info("Result Code: "+ theResult);
            log.Info("Result Message: " + System.Text.Encoding.ASCII.GetString(e).Replace("\0", ""));
            device.Error_code = theResult;
            device.Err_message = System.Text.Encoding.ASCII.GetString(e).Replace("\0", "");
            return device;
        }

        public DeviceReply DeviceClose ()
        {
            DeviceReply device = new DeviceReply();
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_close");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                device.Error_code = -1;
                device.Err_message = "Method Or Function Not Found";
                return device;
            }
            ektp_close ektpClose = (ektp_close)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_close));

            byte[] e = new byte[80];
            int theResult = ektpClose(e);

            device.Error_code = theResult;
            device.Err_message = System.Text.Encoding.ASCII.GetString(e).Replace("\0", "");
            return device;
        }

        #endregion

        #region ~ Finger Login  ~
        public DeviceReply EktpDevice(string fingerTemplate, string nik, string wsid,string hashIso)
        {
            
            DeviceReply device = new DeviceReply();
           
            // Get KTP-EL Device Info Check If Device Active or Pasive State
            var ektpInfo = EktpInfo();
            if (ektpInfo.Error_code > 0 || ektpInfo.Error_code < 0)
                return device = ektpInfo;
            else
                device = ektpInfo;
            // Validasi Finger Login
            //string hashIso = "E0D3CD214E9B26CC42A09FC284756DFA9CA2CDF5";//"737A962837A539EB5D913E4E97984254266ACE44";
            var verifyFinger = VerifyEktpISOTemplate(nik, wsid, fingerTemplate, hashIso);
            if (verifyFinger.Error_code > 0 )
                return device = verifyFinger;
            else
                device = verifyFinger;
            return device;
        }
        

        /*public int SetDeviceToActive()
        {
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_open");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                return -1;
            }
            ektp_open ektpOpen = (ektp_open)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_open));

            byte[] e = new byte[80];
            int theResult = ektpOpen(e);
            var a = System.Text.Encoding.ASCII.GetString(e);
            string b = a.Replace("\0", "");
            return theResult;
        }*/

        // function Finger Print
        public DeviceReply VerifyEktpISOTemplate(string nip, string wsid, string isoTemplate,string hashIsoTemplate)
        {
            // Load configuration
            var logRepository = LogManager.GetRepository(Assembly.GetEntryAssembly());
            XmlConfigurator.Configure(logRepository, new FileInfo("log4net.config"));

            DeviceReply dev = new DeviceReply();
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_verifyIso");
            log.Info("Verify EKTP-EL ISO Template");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                log.Error("Cannot Call ektp_verifyIso");
                dev.Error_code = -1;
                dev.Err_message = "Method Or Function Not Found";
                return dev;
            }
            EKTP_VerifyIsoTemplate verifyIso = (EKTP_VerifyIsoTemplate)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(EKTP_VerifyIsoTemplate));
            
            string isoTempalteDec = isoTemplate;
            byte[] data = System.Text.ASCIIEncoding.ASCII.GetBytes(isoTempalteDec);
            byte[] isoTempalteEnc = System.Text.Encoding.ASCII.GetBytes(isoTempalteDec);
            int timeOut = 300;
            
            int dateTime = 2020090910;//20200909100101001;
            int count = 2;
            byte[] hash = System.Text.ASCIIEncoding.ASCII.GetBytes(hashIsoTemplate);//("E0D3CD214E9B26CC42A09FC284756DFA9CA2CDF5");
            byte[] erro = new byte[80];
            byte[] matchingScore = new byte[80];




            int theResult = verifyIso(erro, nip, isoTempalteEnc, timeOut, wsid, dateTime, count, hash, matchingScore);
            string err = System.Text.Encoding.ASCII.GetString(erro);
            log.Info("Result Code: " + theResult);
            log.Info("Result Message: " + err);
            dev.Error_code = theResult;
            dev.Err_message = err;
            return dev;
        }
        #endregion


        #region ~ KTP El Verification ~

        public DeviceReply PutEKTP()
        {
            DeviceReply dev = new DeviceReply();
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_putKTP");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                dev.Error_code = -1;
                dev.Err_message = "Method Or Function Not Found";
                return dev;
            }
            ektp_putKTP putKtp = (ektp_putKTP)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_putKTP));
            byte[] error = new byte[80];
            byte[] dispMessage = Encoding.ASCII.GetBytes("Tap KTP");
            int timeOut = 300;
            byte[] fingerType = new byte[5 + 1];


            int theResult = putKtp(error, dispMessage, timeOut, fingerType);

            dev.Error_code = theResult;
            dev.Err_message = Encoding.ASCII.GetString(error);
            return dev;
        }

        public DeviceReply GetDataDemography(string idOperator, string nikOperator, string idAuth, string nikAuth,int timeout)
        {
            DeviceReply dev = new DeviceReply();
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_getDataDemography");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                dev.Error_code = -1;
                dev.Err_message = "Method Or Function Not Found";
                return dev;
            }
            ektp_getDataDemography ektpgetDataDemography = (ektp_getDataDemography)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_getDataDemography));

            byte[] error = new byte[20];
            //string error = "";
            //StringBuilder sb = new StringBuilder(1000);
            IntPtr pointers = new IntPtr();
            int theResult = ektpgetDataDemography(error, timeout, idOperator, nikOperator, idAuth, nikAuth,ref pointers);


            //string data = sb.ToString();
            string data = Marshal.PtrToStringAnsi(pointers);

            data = data.Replace("\"", "");
            string[] array = data.Split(',');
            Demography demo = new Demography();
            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = true
            };
            demo.Nik = array[0].ToString().Split("=")[1].ToString();
            demo.Name = array[1].ToString().Split("=")[1].ToString();
            demo.Address = array[2].ToString().Split("=")[1].ToString();

            demo.PlaceOfBirth = array[3].ToString().Split("=")[1].ToString();
            demo.DateOfBirth = array[4].ToString().Split("=")[1].ToString();
            demo.Gender = array[5].ToString().Split("=")[1].ToString();

            demo.RT = array[6].ToString().Split("=")[1].ToString();
            demo.RW = array[7].ToString().Split("=")[1].ToString();
            demo.Village = array[8].ToString().Split("=")[1].ToString();

            demo.SubDistrict = array[9].ToString().Split("=")[1].ToString();
            demo.City = array[10].ToString().Split("=")[1].ToString();
            demo.Province = array[11].ToString().Split("=")[1].ToString();

            demo.BloodType = array[12].ToString().Split("=")[1].ToString();
            demo.Religion = array[13].ToString().Split("=")[1].ToString();
            demo.MaritalStatus = array[14].ToString().Split("=")[1].ToString();
            demo.Occupation = array[15].ToString().Split("=")[1].ToString();
            demo.Nationality = array[16].ToString().Split("=")[1].ToString();
            demo.PlaceOfIssue = array[17].ToString().Split("=")[1].ToString();
            string err_msg = "";
            if (theResult == 0)
            {
                err_msg = JsonSerializer.Serialize(demo, options);
            }
            else
            {
                //err_msg = Encoding.ASCII.GetString(error);
                err_msg = "";//error;
            }
            dev.Error_code = theResult;

            dev.Err_message = err_msg;
            return dev;
        }

        public DeviceReply VerifyFinger(string fingerType,string operatorId,string operatorNik)
        {
            
            DeviceReply dev = new DeviceReply();
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "ektp_verifyFinger");
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                dev.Error_code = -1;
                dev.Err_message = "Method Or Function Not Found";
                return dev;
            }
            ektp_verifyFinger verifyFinger = (ektp_verifyFinger)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(ektp_verifyFinger));
            byte[] error = new byte[80];
            byte[] dispMessage = Encoding.ASCII.GetBytes("Tap KTP");
            int timeOut = 3000;
            byte[] _fingerType = Encoding.ASCII.GetBytes(fingerType);//new byte[5 + 1];
            byte [] _operatorId = Encoding.ASCII.GetBytes(operatorId);//new byte[20]; --> userDomain
            byte[] _operatorNik = Encoding.ASCII.GetBytes(operatorNik); //new byte[20]; --> user NIK

            int theResult = verifyFinger(error, dispMessage, timeOut, _fingerType, _operatorId,_operatorNik);
            string err = System.Text.Encoding.ASCII.GetString(error);

            dev.Error_code = theResult;
            dev.Err_message = err;
            return dev;
        }


        #endregion

        #region ~ PASPOR BCA Verification ~ 

        public int PinpadOpen()
        {
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(this.pDll, "_PinpadOpen");
            //oh dear, error handling here
            if (pAddressOfFunctionToCall == IntPtr.Zero)
            {
                return -1;
            }

            _PinpadOpen pinpadOpen = (_PinpadOpen)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(_PinpadOpen));
            byte[] e = new byte[80];
            int theResult = pinpadOpen(1);
            return theResult;
        }

        public bool closeLibraryPinpad()
        {
            this.Reset();
            this.Close();
            bool result = NativeMethods.FreeLibrary(this.pDll);


            return result;
        }

        public int Reset()
        {
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(pDll, "_PinpadReset");

            _PinpadReset pinpadReset = (_PinpadReset)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall,
                                                                                        typeof(_PinpadReset));
            return pinpadReset();

        }

        public int Close()
        {
            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(pDll, "_PinpadClose");

            _PinpadClose pinpadClose = (_PinpadClose)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall,
                                                                                        typeof(_PinpadClose));
            return pinpadClose();

        }


        //public string SwipeCard(string text)
        public DeviceReply SwipeCard(string text)
        {
            DeviceReply dev = new DeviceReply();
            PP_DISPPARM pp_dispparm = new PP_DISPPARM
            {
                text = new byte[40 + 1],
                offset = (byte)0,
                clear_lines = (byte)(1 | 2),
                reserved = new byte[4],
            };

            PP_MSR pp_msr = new PP_MSR();

            byte[] tempB = Encoding.ASCII.GetBytes(text);

            for (int i = 0; i < Math.Min(tempB.Length, 40); i++)
            {
                pp_dispparm.text[i] = tempB[i];
            };
            pp_dispparm.text[Math.Min(tempB.Length, 40)] = 0;

            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(pDll, "_PinpadMSRRead");

            _PinpadMSRRead pinpadMSRRead = (_PinpadMSRRead)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall,
                                                                                       typeof(_PinpadMSRRead));

            int result = pinpadMSRRead((byte)30, ref pp_dispparm, ref pp_msr);
            string err_msg = "";
            string trak2 = Encoding.ASCII.GetString(pp_msr.data2);
            Hashtable errTable = new Hashtable();
            errTable.Add(0, "operation was successful");
            errTable.Add(1, "processing PIN request");
            errTable.Add(2, "invalid field");
            errTable.Add(3, "a parameter value was incorrect");
            errTable.Add(12, "incorrect command or response length");
            errTable.Add(32, "data entry cancelled by user");
            errTable.Add(33, "operation timed out");
            errTable.Add(34, "MSR track read error");
            errTable.Add(87, "pinpad is not responding");
            errTable.Add(89, "comms error occurred");
            errTable.Add(96, "card inserted but no chip detected");
            errTable.Add(97, "transaction no complete");
            errTable.Add(98, "invalid data on chip or no tracks were able to read from the chip");
            errTable.Add(997, "an unknown response rxed from pinpad");
            errTable.Add(998, "bad parameter passed to API");
            if (trak2 != "")
            {
                string cardNo = trak2.Split('=')[0];
                err_msg = cardNo;
            }
            else
            {
                bool checkKey = errTable.ContainsKey(result);

                err_msg = checkKey == true ? errTable[result].ToString() : "";
            }
            dev.Error_code = result;
            dev.Err_message = err_msg;
            return dev;
        }

        //public string GetPin(string textDisplay, string cardNo)
        public DeviceReply GetPin(string textDisplay, string cardNo)
        {
            DeviceReply dev = new DeviceReply();
            PP_DISPPARM pp_dispparm = new PP_DISPPARM
            {
                text = new byte[40 + 1],
                offset = (byte)0,
                clear_lines = (byte)(1 | 2),
                reserved = new byte[4],
            };

            PP_PINPARM pp_pinpadrm = new PP_PINPARM
            {
                mindigits = (byte)6,
                maxdigits = (byte)6,
                timeout = (byte)30,
                offset = (byte)20,
                beep = (byte)1,
                format = (byte)0,
                keyid = (byte)2,
                PANdata = new byte[20],
                reserved = new byte[4],
            };



            byte[] tempB = Encoding.ASCII.GetBytes(textDisplay);

            for (int i = 0; i < Math.Min(tempB.Length, 40); i++)
            {
                pp_dispparm.text[i] = tempB[i];
            };
            pp_dispparm.text[Math.Min(tempB.Length, 40)] = 0;

            //card
            byte[] tempC = Encoding.ASCII.GetBytes(cardNo);

            for (int i = 0; i < Math.Min(tempC.Length, 20); i++)
            {
                pp_pinpadrm.PANdata[i] = tempC[i];
            };
            pp_pinpadrm.PANdata[Math.Min(tempC.Length, 20)] = 0;




            byte[] buffer = new byte[8];


            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(pDll, "_PinpadGetPIN");

            _PinpadGetPIN pinpadGetPin = (_PinpadGetPIN)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall, typeof(_PinpadGetPIN));

            int result = pinpadGetPin(ref pp_dispparm, ref pp_pinpadrm, buffer);

            Console.WriteLine("pin :" + buffer);
            Hashtable errTable = new Hashtable();
            errTable.Add(0, "operation was successful");
            errTable.Add(1, "processing PIN request");
            errTable.Add(2, "invalid field");
            errTable.Add(3, "a parameter value was incorrect");
            errTable.Add(12, "incorrect command or response length");
            errTable.Add(32, "data entry cancelled by user");
            errTable.Add(33, "operation timed out");
            errTable.Add(34, "MSR track read error");
            errTable.Add(87, "pinpad is not responding");
            errTable.Add(89, "comms error occurred");
            errTable.Add(96, "card inserted but no chip detected");
            errTable.Add(97, "transaction no complete");
            errTable.Add(98, "invalid data on chip or no tracks were able to read from the chip");
            errTable.Add(997, "an unknown response rxed from pinpad");
            errTable.Add(998, "bad parameter passed to API");
            string hsl_cvt = toHexa(buffer);
            string err_msg = "";
            if (result == 0)
            {
                err_msg = toHexa(buffer);
            }
            else
            {
                bool checkKey = errTable.ContainsKey(result);
                err_msg = checkKey == true ? errTable[result].ToString() : "";
            }
            dev.Error_code = result;
            dev.Err_message = err_msg;

            return dev;
        }

        public int ChangeText(string text)
        {

            PP_DISPPARM pp_dispparm = new PP_DISPPARM
            {
                text = new byte[40 + 1],
                offset = (byte)0,
                clear_lines = (byte)(1 | 2),
                reserved = new byte[4],
            };

            byte[] tempB = Encoding.ASCII.GetBytes(text);

            for (int i = 0; i < Math.Min(tempB.Length, 40); i++)
            {
                pp_dispparm.text[i] = tempB[i];
            };
            pp_dispparm.text[Math.Min(tempB.Length, 40)] = 0;

            // pp_dispparm.text = Encoding.ASCII.GetBytes(text);

            IntPtr pAddressOfFunctionToCall = NativeMethods.GetProcAddress(pDll, "_PinpadDisplay");

            _PinpadDisplay pinpadDisplay = (_PinpadDisplay)Marshal.GetDelegateForFunctionPointer(pAddressOfFunctionToCall,
                                                                                       typeof(_PinpadDisplay));

            int result = pinpadDisplay(ref pp_dispparm);

            return result;
        }

        public String toHexa(byte[] raw)
        {
            byte[] HEX_CHAR_TABLE = { (byte) '0', (byte) '1', (byte) '2',
                (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7',
                (byte) '8', (byte) '9', (byte) 'a', (byte) 'b', (byte) 'c',
                (byte) 'd', (byte) 'e', (byte) 'f' };

            byte[] hex = new byte[2 * raw.Length];
            int index = 0;

            foreach (byte b in raw)
            {
                int v = b & 0xFF;
                hex[index++] = HEX_CHAR_TABLE[v >> 4];
                hex[index++] = HEX_CHAR_TABLE[v & 0xF];
            }

            String result = "";
            ASCIIEncoding ascii = new ASCIIEncoding();
            try
            {
                result = ascii.GetString(hex).ToUpper();
            }
            catch (Exception ex)
            {

            }
            return result;
        }

        #endregion
    }
}
