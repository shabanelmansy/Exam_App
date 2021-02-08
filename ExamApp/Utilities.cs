using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace ExamApp
{
    class Utilities
    {
        public void KillAllAplication()
        {

            // hide taskbar
            Taskbar.Hide();
            //Kill All Browsers
            KillAllBrowsers();


        }

        public static void KillAllBrowsers()
        {
            try
            {
                Process[] AllProcesses = Process.GetProcesses();
                foreach (var process in AllProcesses)
                {
                    if (process.MainWindowTitle != "")
                    {
                        string s = process.ProcessName.ToLower();
                        if ((s == "microsoftedgecp" ||
                            s == "microsoftedge" ||
                            s == "msedge" ||
                            s == "opera" ||
                            s == "iexplore" ||
                            s == "iexplorer" ||
                            //s == "chrome" ||
                            s == "firefox")
                            )
                            process.Kill();
                    }
                }
            }
            catch { }
        }


        public void SetTaskManager(bool enable)
        {
            RegistryKey objRegistryKey = Registry.CurrentUser.CreateSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Policies\System");
            if (enable && objRegistryKey.GetValue("DisableTaskMgr") != null)
                objRegistryKey.DeleteValue("DisableTaskMgr");
            else
                objRegistryKey.SetValue("DisableTaskMgr", "1");
            objRegistryKey.Close();
        }
    }

}
