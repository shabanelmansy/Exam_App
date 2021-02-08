using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using CefSharp;
using CefSharp.WinForms;

namespace ExamApp
{
    public partial class Form1 : Form
    {
        KeyboardHook keyboardHook;
        Utilities utilities;

        public ChromiumWebBrowser chromeBrowser;

        public Form1()
        {
            InitializeComponent();
            keyboardHook = new KeyboardHook();
            utilities = new Utilities();
            utilities.SetTaskManager(false);
            utilities.KillAllAplication();
            keyboardHook.Start();
            InitializeChromium();

        }

        public void InitializeChromium()
        {
            CefSettings settings = new CefSettings();

            // Initialize cef with a command line argument
            // In this case the enable-media-stream flag that allows you to access the camera and the microphone
            settings.CefCommandLineArgs.Add("enable-media-stream", "1");

            Cef.Initialize(settings);

            // Create a browser component
            chromeBrowser = new ChromiumWebBrowser("http://192.168.100.183/etco/khalil/index.html");
            // Add it to the form and fill it to the form window.
            this.Controls.Add(chromeBrowser);
            chromeBrowser.Dock = DockStyle.Fill;
            chromeBrowser.JavascriptObjectRepository.Register("closeExamAsync", new ExamObject(), true);

        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {

            Taskbar.Show();
            keyboardHook.Stop();
            utilities.SetTaskManager(true);
            Cef.Shutdown();
        }
    }
}
