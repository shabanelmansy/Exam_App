using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;

namespace ExamApp
{
    class KeyboardHook
    {
		private ConcurrentDictionary<Guid, KeyboardHook> KeyboardHooks = new ConcurrentDictionary<Guid, KeyboardHook>();
		private Guid? hookId;

		private bool altPressed, ctrlPressed;
		private IntPtr handle;
		private KeyboardHookCallback callback;
		private HookDelegate hookDelegate;

		internal Guid Id { get; private set; }

		internal KeyboardHook()
		{
			this.callback = KeyboardHookCallback;
		}
		public void Start()
		{
			hookId = RegisterKeyboardHook();
		}

		public void Stop()
		{
			if (hookId.HasValue)
			{
				DeregisterKeyboardHook(hookId.Value);
			}
		}

		private bool KeyboardHookCallback(int keyCode, KeyModifier modifier, KeyState state)
		{
			var block = false;
            var key = KeyInterop.KeyFromVirtualKey(keyCode);

            block |= key == Key.Apps;
            block |= key == Key.Escape && modifier == KeyModifier.None;
            block |= key == Key.F1;
            block |= key == Key.F2;
            block |= key == Key.F3;
            //block |= key == Key.F4;
            block |= key == Key.F5;
            block |= key == Key.F6;
            block |= key == Key.F7;
            block |= key == Key.F8;
            block |= key == Key.F9;
            block |= key == Key.F10;
            block |= key == Key.F11;
            block |= key == Key.F12;
            block |= key == Key.LWin;
            block |= key == Key.PrintScreen;
            block |= key == Key.RWin;
            block |= modifier.HasFlag(KeyModifier.Alt) && key == Key.Escape;
            //block |= modifier.HasFlag(KeyModifier.Alt) && key == Key.F4;
            block |= modifier.HasFlag(KeyModifier.Alt) && key == Key.Space;
            block |= modifier.HasFlag(KeyModifier.Alt) && key == Key.Tab;
            block |= modifier.HasFlag(KeyModifier.Ctrl) && key == Key.Escape;

            if (block)
			{
				// Log(key, keyCode, modifier, state);
			}

			return block;
		}

		internal void Attach()
		{
			var process = System.Diagnostics.Process.GetCurrentProcess();
			var module = process.MainModule;
			var moduleHandle = Kernel32.GetModuleHandle(module.ModuleName);

			// IMPORTANT:
			// Ensures that the hook delegate does not get garbage collected prematurely, as it will be passed to unmanaged code.
			// Not doing so will result in a <c>CallbackOnCollectedDelegate</c> error and subsequent application crash!
			hookDelegate = new HookDelegate(LowLevelKeyboardProc);
			handle = User32.SetWindowsHookEx(HookType.WH_KEYBOARD_LL, hookDelegate, moduleHandle, 0);
		}

		public void DeregisterKeyboardHook(Guid hookId)
		{
			var hook = KeyboardHooks.Values.FirstOrDefault(h => h.Id == hookId);

			if (hook != null)
			{
				var success = hook.Detach();

				if (!success)
				{
					throw new Win32Exception(Marshal.GetLastWin32Error());
				}

				KeyboardHooks.TryRemove(hookId, out _);
			}
		}

		public Guid RegisterKeyboardHook()
		{
			var hookId = default(Guid);
			var hookReadyEvent = new AutoResetEvent(false);
			var hookThread = new Thread(() =>
			{
				var hook = new KeyboardHook();
				var sleepEvent = new AutoResetEvent(false);

				hook.Attach();
				hookId = hook.Id;
				KeyboardHooks[hookId] = hook;
				hookReadyEvent.Set();

				while (true)
				{
					sleepEvent.WaitOne();
				}
			});

			hookThread.SetApartmentState(ApartmentState.STA);
			hookThread.IsBackground = true;
			hookThread.Start();

			hookReadyEvent.WaitOne();

			return hookId;
		}
		internal bool Detach()
		{
			return User32.UnhookWindowsHookEx(handle);
		}

		private IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam)
		{
			if (nCode >= 0)
			{
				var keyData = (KBDLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(KBDLLHOOKSTRUCT));
				var modifier = GetModifiers(keyData, wParam.ToInt32());
				var state = GetState(wParam.ToInt32());

				if (callback((int)keyData.KeyCode, modifier, state))
				{
					return (IntPtr)1;
				}
			}

			return User32.CallNextHookEx(handle, nCode, wParam, lParam);
		}

		private KeyState GetState(int wParam)
		{
			switch (wParam)
			{
				case Constant.WM_KEYDOWN:
				case Constant.WM_SYSKEYDOWN:
					return KeyState.Pressed;
				case Constant.WM_KEYUP:
				case Constant.WM_SYSKEYUP:
					return KeyState.Released;
				default:
					return KeyState.Unknown;
			}
		}

		private KeyModifier GetModifiers(KBDLLHOOKSTRUCT keyData, int wParam)
		{
			var modifier = KeyModifier.None;

			TrackCtrlAndAlt(keyData, wParam);

			if (altPressed || keyData.Flags.HasFlag(KBDLLHOOKSTRUCTFlags.LLKHF_ALTDOWN))
			{
				modifier |= KeyModifier.Alt;
			}

			if (ctrlPressed)
			{
				modifier |= KeyModifier.Ctrl;
			}

			return modifier;
		}

		private void TrackCtrlAndAlt(KBDLLHOOKSTRUCT keyData, int wParam)
		{
			var keyCode = keyData.KeyCode;

			if (keyCode == (uint)VirtualKeyCode.LeftControl || keyCode == (uint)VirtualKeyCode.RightControl)
			{
				ctrlPressed = IsPressed(wParam);
			}
			else if (keyCode == (uint)VirtualKeyCode.LeftAlt || keyCode == (uint)VirtualKeyCode.RightAlt)
			{
				altPressed = IsPressed(wParam);
			}

			if (ctrlPressed && altPressed && keyCode == (uint)VirtualKeyCode.Delete)
			{
				// When the Secure Attention Sequence is pressed, the WM_KEYUP / WM_SYSKEYUP messages for CTRL and ALT get lost...
				ctrlPressed = false;
				altPressed = false;
			}
		}

		private bool IsPressed(int wParam)
		{
			return wParam == Constant.WM_KEYDOWN || wParam == Constant.WM_SYSKEYDOWN;
		}
	}

	internal static class User32
	{
		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool CloseClipboard();

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool CloseDesktop(IntPtr hDesktop);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr lpszDevice, IntPtr pDevmode, int dwFlags, uint dwDesiredAccess, IntPtr lpsa);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool BringWindowToTop(IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool EmptyClipboard();

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool EnumDesktops(IntPtr hwinsta, EnumDesktopDelegate lpEnumFunc, IntPtr lParam);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool EnumWindows(EnumWindowsDelegate enumProc, IntPtr lParam);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool GetCursorPos(ref POINT pt);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr GetThreadDesktop(int dwThreadId);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr GetProcessWindowStation();

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, IntPtr pvInfo, int nLength, ref int lpnLengthNeeded);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool GetWindowPlacement(IntPtr hWnd, ref WINDOWPLACEMENT lpwndpl);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern int GetWindowText(IntPtr hWnd, StringBuilder strText, int maxCount);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern int GetWindowTextLength(IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool IsWindowVisible(IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool OpenClipboard(IntPtr hWndNewOwner);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool SetForegroundWindow(IntPtr hWnd);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr SetWinEventHook(uint eventMin, uint eventMax, IntPtr hmodWinEventProc, EventDelegate lpfnWinEventProc, uint idProcess, uint idThread, uint dwFlags);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern IntPtr SetWindowsHookEx(HookType hookType, HookDelegate lpfn, IntPtr hMod, uint dwThreadId);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool SwitchDesktop(IntPtr hDesktop);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool SystemParametersInfo(SPI uiAction, uint uiParam, ref RECT pvParam, SPIF fWinIni);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool SystemParametersInfo(SPI uiAction, int uiParam, string pvParam, SPIF fWinIni);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool UnhookWinEvent(IntPtr hWinEventHook);

		[DllImport("user32.dll", SetLastError = true)]
		internal static extern bool UnhookWindowsHookEx(IntPtr hhk);
	}
	internal delegate IntPtr HookDelegate(int nCode, IntPtr wParam, IntPtr lParam);

	internal enum SPI : uint
	{
		/// <summary>
		/// Retrieves the full path of the bitmap file for the desktop wallpaper. The pvParam parameter must point to a buffer
		/// that receives a null-terminated path string. Set the uiParam parameter to the size, in characters, of the pvParam buffer.
		/// The returned string will not exceed MAX_PATH characters. If there is no desktop wallpaper, the returned string is empty.
		/// </summary>
		GETDESKWALLPAPER = 0x73,

		/// <summary>
		/// Retrieves the size of the work area on the primary display monitor. The work area is the portion of the screen
		/// not obscured by the system taskbar or by application desktop toolbars. The pvParam parameter must point to a
		/// RECT structure that receives the coordinates of the work area, expressed in virtual screen coordinates. To get
		/// the work area of a monitor other than the primary display monitor, call the GetMonitorInfo function.
		/// </summary>
		GETWORKAREA = 0x30,

		/// <summary>
		/// Sets the desktop wallpaper. The value of the pvParam parameter determines the new wallpaper. To specify a wallpaper bitmap,
		/// set pvParam to point to a null-terminated string containing the name of a bitmap file. Setting pvParam to "" removes the
		/// wallpaper. Setting pvParam to SETWALLPAPER_DEFAULT or null reverts to the default wallpaper.
		/// </summary>
		SETDESKWALLPAPER = 0x14,

		/// <summary>
		/// Sets the size of the work area. The work area is the portion of the screen not obscured by the system taskbar
		/// or by application desktop toolbars. The pvParam parameter is a pointer to a RECT structure that specifies the
		/// new work area rectangle, expressed in virtual screen coordinates. In a system with multiple display monitors,
		/// the function sets the work area of the monitor that contains the specified rectangle.
		/// </summary>
		SETWORKAREA = 0x2F,
	}

	internal delegate void EventDelegate(IntPtr hWinEventHook, uint eventType, IntPtr hwnd, int idObject, int idChild, uint dwEventThread, uint dwmsEventTime);
	internal delegate bool EnumWindowsDelegate(IntPtr hWnd, IntPtr lParam);

	public delegate bool KeyboardHookCallback(int keyCode, KeyModifier modifier, KeyState state);


	[StructLayout(LayoutKind.Sequential)]
	internal struct POINT
	{
		internal int X;
		internal int Y;
	}

	internal class Kernel32
	{
		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern bool CloseHandle(IntPtr hObject);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern bool CreateProcess(
			string lpApplicationName,
			string lpCommandLine,
			IntPtr lpProcessAttributes,
			IntPtr lpThreadAttributes,
			bool bInheritHandles,
			int dwCreationFlags,
			IntPtr lpEnvironment,
			string lpCurrentDirectory,
			ref STARTUPINFO lpStartupInfo,
			ref PROCESS_INFORMATION lpProcessInformation);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern int GetCurrentThreadId();

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern IntPtr GetModuleHandle(string lpModuleName);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern int ResumeThread(IntPtr hThread);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);

		[DllImport("kernel32.dll", SetLastError = true)]
		internal static extern int SuspendThread(IntPtr hThread);
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}
	[Flags]
	public enum EXECUTION_STATE : uint
	{
		AWAYMODE_REQUIRED = 0x00000040,
		CONTINUOUS = 0x80000000,
		DISPLAY_REQUIRED = 0x00000002,
		SYSTEM_REQUIRED = 0x00000001
	}

	[Flags]
	internal enum ThreadAccess : int
	{
		TERMINATE = 0x1,
		SUSPEND_RESUME = 0x2,
		GET_CONTEXT = 0x8,
		SET_CONTEXT = 0x10,
		SET_INFORMATION = 0x20,
		QUERY_INFORMATION = 0x40,
		SET_THREAD_TOKEN = 0x80,
		IMPERSONATE = 0x100,
		DIRECT_IMPERSONATION = 0x200
	}

	[Flags]
	internal enum SPIF
	{
		NONE = 0x00,

		/// <summary>
		/// Writes the new system-wide parameter setting to the user profile.
		/// </summary>
		UPDATEINIFILE = 0x01,

		/// <summary>
		/// Broadcasts the WM_SETTINGCHANGE message after updating the user profile.
		/// </summary>
		SENDCHANGE = 0x02,

		/// <summary>
		/// Performs UPDATEINIFILE and SENDCHANGE.
		/// </summary>
		UPDATEANDCHANGE = 0x03
	}

	internal struct WINDOWPLACEMENT
	{
		public int length;
		public int flags;
		public int showCmd;
		public Point ptMinPosition;
		public Point ptMaxPosition;
		public Rectangle rcNormalPosition;
	}
	internal delegate bool EnumDesktopDelegate(string lpszDesktop, IntPtr lParam);

	[StructLayout(LayoutKind.Sequential)]
	internal struct STARTUPINFO
	{
		public int cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public int dwX;
		public int dwY;
		public int dwXSize;
		public int dwYSize;
		public int dwXCountChars;
		public int dwYCountChars;
		public int dwFillAttribute;
		public int dwFlags;
		public short wShowWindow;
		public short cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct RECT
	{
		internal int Left;
		internal int Top;
		internal int Right;
		internal int Bottom;

		internal IBounds ToBounds()
		{
			return new Bounds
			{
				Left = Left,
				Top = Top,
				Right = Right,
				Bottom = Bottom
			};
		}
	}
	public interface IBounds
	{
		int Left { get; }
		int Top { get; }
		int Right { get; }
		int Bottom { get; }
	}
	internal class Bounds : IBounds
	{
		public int Left { get; set; }
		public int Top { get; set; }
		public int Right { get; set; }
		public int Bottom { get; set; }
	}

	internal enum HookType
	{
		/// <summary>
		/// Installs a hook procedure that records input messages posted to the system message queue. This hook is useful for recording
		/// macros. For more information, see the JournalRecordProc hook procedure.
		/// </summary>
		WH_JOURNALRECORD = 0,

		/// <summary>
		/// Installs a hook procedure that posts messages previously recorded by a WH_JOURNALRECORD hook procedure. For more information,
		/// see the JournalPlaybackProc hook procedure.
		/// </summary>
		WH_JOURNALPLAYBACK = 1,

		/// <summary>
		/// Installs a hook procedure that monitors keystroke messages. For more information, see the KeyboardProc hook procedure.
		/// </summary>
		WH_KEYBOARD = 2,

		/// <summary>
		/// Installs a hook procedure that monitors messages posted to a message queue. For more information, see the GetMsgProc hook
		/// procedure.
		/// </summary>
		WH_GETMESSAGE = 3,

		/// <summary>
		/// Installs a hook procedure that monitors messages before the system sends them to the destination window procedure. For more
		/// information, see the CallWndProc hook procedure.
		/// </summary>
		WH_CALLWNDPROC = 4,

		/// <summary>
		/// Installs a hook procedure that receives notifications useful to a CBT application. For more information, see the CBTProc hook
		/// procedure.
		/// </summary>
		WH_CBT = 5,

		/// <summary>
		/// Installs a hook procedure that monitors messages generated as a result of an input event in a dialog box, message box,  menu,
		/// or scroll bar. The hook procedure monitors these messages for all applications in the same desktop as the calling thread. For
		/// more information, see the SysMsgProc hook procedure.
		/// </summary>
		WH_SYSMSGFILTER = 6,

		/// <summary>
		/// Installs a hook procedure that monitors mouse messages. For more information, see the MouseProc hook procedure.
		/// </summary>
		WH_MOUSE = 7,

		WH_HARDWARE = 8,

		/// <summary>
		/// Installs a hook procedure useful for debugging other hook procedures. For more information, see the DebugProc hook procedure.
		/// </summary>
		WH_DEBUG = 9,

		/// <summary>
		/// Installs a hook procedure that receives notifications useful to shell applications. For more information, see the ShellProc
		/// hook procedure.
		/// </summary>
		WH_SHELL = 10,

		/// <summary>
		/// Installs a hook procedure that will be called when the application's foreground thread is about to become idle. This hook is
		/// useful for performing low priority tasks during idle time. For more information, see the ForegroundIdleProc hook procedure. 
		/// </summary>
		WH_FOREGROUNDIDLE = 11,

		/// <summary>
		/// Installs a hook procedure that monitors messages after they have been processed by the destination window procedure. For more
		/// information, see the CallWndRetProc hook procedure.
		/// </summary>
		WH_CALLWNDPROCRET = 12,

		/// <summary>
		/// Installs a hook procedure that monitors low-level keyboard input events. For more information, see the LowLevelKeyboardProc
		/// hook procedure.
		/// </summary>
		WH_KEYBOARD_LL = 13,

		/// <summary>
		/// Installs a hook procedure that monitors low-level mouse input events. For more information, see the LowLevelMouseProc hook
		/// procedure.
		/// </summary>
		WH_MOUSE_LL = 14
	}

	public enum KeyState
	{
		Unknown = 0,
		Pressed,
		Released
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct KBDLLHOOKSTRUCT
	{
		/// <summary>
		/// A virtual-key code. The code must be a value in the range 1 to 254. 
		/// </summary>
		internal uint KeyCode;

		/// <summary>
		/// A hardware scan code for the key. 
		/// </summary>
		internal uint ScanCode;

		/// <summary>
		/// The extended-key flag, event-injected flags, context code, and transition-state flag. This member is specified as follows. An
		/// application can use the following values to test the keystroke flags. Testing LLKHF_INJECTED (bit 4) will tell you whether the
		/// event was injected. If it was, then testing LLKHF_LOWER_IL_INJECTED (bit 1) will tell you whether or not the event was injected
		/// from a process running at lower integrity level.
		/// </summary>
		internal KBDLLHOOKSTRUCTFlags Flags;

		/// <summary>
		/// The time stamp for this message, equivalent to what <c>GetMessageTime</c> would return for this message.
		/// </summary>
		internal uint Time;

		/// <summary>
		/// Additional information associated with the message. 
		/// </summary>
		internal IntPtr DwExtraInfo;
	}
	internal enum KBDLLHOOKSTRUCTFlags
	{
		/// <summary>
		/// Test the extended-key flag. 
		/// </summary>
		LLKHF_EXTENDED = 0x01,

		/// <summary>
		/// Test the event-injected (from any process) flag.
		/// </summary>
		LLKHF_INJECTED = 0x10,

		/// <summary>
		/// Test the context code. 
		/// </summary>
		LLKHF_ALTDOWN = 0x20,

		/// <summary>
		/// Test the transition-state flag. 
		/// </summary>
		LLKHF_UP = 0x80
	}
	internal enum VirtualKeyCode
	{
		A = 0x41,
		Q = 0x51,
		Delete = 0x2E,
		LeftAlt = 0xA4,
		LeftControl = 0xA2,
		LeftWindows = 0x5B,
		RightAlt = 0xA5,
		RightControl = 0xA3
	}
	[Flags]
	public enum KeyModifier
	{
		None = 0,
		Alt = 0b1,
		Ctrl = 0b10
	}

	internal static class Constant
	{
		/// <summary>
		/// A window has received mouse capture. This event is sent by the system, never by servers.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/dd318066(v=vs.85).aspx.
		/// </summary>
		internal const uint EVENT_SYSTEM_CAPTURESTART = 0x8;

		/// <summary>
		/// The foreground window has changed. The system sends this event even if the foreground window has changed to another window in
		/// the same thread. Server applications never send this event.
		/// For this event, the WinEventProc callback function's hwnd parameter is the handle to the window that is in the foreground, the
		/// idObject parameter is OBJID_WINDOW, and the idChild parameter is CHILDID_SELF.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/dd318066(v=vs.85).aspx.
		/// </summary>
		internal const uint EVENT_SYSTEM_FOREGROUND = 0x3;

		/// <summary>
		/// The large icon of a window. See https://docs.microsoft.com/en-us/windows/win32/winmsg/wm-geticon#parameters.
		/// </summary>
		internal const int ICON_BIG = 1;

		/// <summary>
		/// The small icon of a window. See https://docs.microsoft.com/en-us/windows/win32/winmsg/wm-geticon#parameters.
		/// </summary>
		internal const int ICON_SMALL = 0;

		/// <summary>
		/// The small icon of an application. If an application does not provide one, the system uses a system-generated icon for a window.
		/// See https://docs.microsoft.com/en-us/windows/win32/winmsg/wm-geticon#parameters.
		/// </summary>
		internal const int ICON_SMALL2 = 2;

		/// <summary>
		/// Minimize all open windows.
		/// </summary>
		internal const int MIN_ALL = 419;

		/// <summary>
		/// Bitmask to evaluate the origin of a mouse event.
		/// 
		/// See https://docs.microsoft.com/en-us/windows/desktop/tablet/system-events-and-mouse-messages.
		/// </summary>
		internal const uint MOUSEEVENTF_MASK = 0xFFFFFF00;

		/// <summary>
		/// The constant for a mouse event generated by a touch interface.
		/// 
		/// See https://docs.microsoft.com/en-us/windows/desktop/tablet/system-events-and-mouse-messages.
		/// </summary>
		internal const uint MOUSEEVENTF_FROMTOUCH = 0xFF515700;

		/// <summary>
		/// Specifies the default priority class for processes, i.e. a process with no special scheduling needs.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms686219(v=vs.85).aspx.
		/// </summary>
		internal const int NORMAL_PRIORITY_CLASS = 0x20;

		/// <summary>
		/// Standard access rights required for a desktop.
		/// 
		/// See https://docs.microsoft.com/de-de/windows/desktop/SecAuthZ/standard-access-rights.
		/// </summary>
		internal const int STANDARD_RIGHTS_REQUIRED = 0xF0000;

		/// <summary>
		/// The constant for the name of a user object.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms683238(v=vs.85).aspx.
		/// </summary>
		internal const int UOI_NAME = 2;

		/// <summary>
		/// The callback function is not mapped into the address space of the process that generates the event. Because the hook function
		/// is called across process boundaries, the system must queue events. Although this method is asynchronous, events are guaranteed
		/// to be in sequential order.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/dd373640(v=vs.85).aspx.
		/// </summary>
		internal const uint WINEVENT_OUTOFCONTEXT = 0x0;

		/// <summary>
		/// Sent when the user selects a command item from a menu, when a control sends a notification message to its parent window, or
		/// when an accelerator keystroke is translated.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms647591(v=vs.85).aspx.
		/// </summary>
		internal const int WM_COMMAND = 0x111;

		/// <summary>
		/// Sent to a window to retrieve a handle to the large or small icon associated with a window. The system displays the large icon
		/// in the ALT+TAB dialog, and the small icon in the window caption.
		/// 
		/// See https://docs.microsoft.com/en-us/windows/win32/winmsg/wm-geticon.
		/// </summary>
		internal const int WM_GETICON = 0x7F;

		/// <summary>
		/// Posted to the window with the keyboard focus when a nonsystem key is pressed. A nonsystem key is a key that is pressed when
		/// the ALT key is not pressed.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646280(v=vs.85).aspx.
		/// </summary>
		internal const int WM_KEYDOWN = 0x100;

		/// <summary>
		/// Posted to the window with the keyboard focus when a nonsystem key is released. A nonsystem key is a key that is pressed when
		/// the ALT key is not pressed, or a keyboard key that is pressed when a window has the keyboard focus.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646281(v=vs.85).aspx.
		/// </summary>
		internal const int WM_KEYUP = 0x101;

		/// <summary>
		/// Posted when the user presses the left mouse button while the cursor is in the client area of a window. If the mouse is not
		/// captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms645607(v=vs.85).aspx.
		/// </summary>
		internal const int WM_LBUTTONDOWN = 0x201;

		/// <summary>
		/// Posted when the user releases the left mouse button while the cursor is in the client area of a window. If the mouse is not
		/// captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms645608(v=vs.85).aspx.
		/// </summary>
		internal const int WM_LBUTTONUP = 0x202;

		/// <summary>
		/// Posted when the user presses the middle mouse button while the cursor is in the client area of a window. If the mouse is not
		/// captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms645610(v=vs.85).aspx.
		/// </summary>
		internal const int WM_MBUTTONDOWN = 0x207;

		/// <summary>
		/// Posted when the user releases the middle mouse button while the cursor is in the client area of a window. If the mouse is not
		/// captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms645611(v=vs.85).aspx.
		/// </summary>
		internal const int WM_MBUTTONUP = 0x208;

		/// <summary>
		/// Posted to a window when the cursor moves. If the mouse is not captured, the message is posted to the window that contains the
		/// cursor. Otherwise, the message is posted to the window that has captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms645616(v=vs.85).aspx.
		/// </summary>
		internal const int WM_MOUSEMOVE = 0x200;

		/// <summary>
		/// Sent to the focus window when the mouse wheel is rotated. The DefWindowProc function propagates the message to the window's
		/// parent. There should be no internal forwarding of the message, since DefWindowProc propagates it up the parent chain until i
		/// finds a window that processes it.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms645617(v=vs.85).aspx.
		/// </summary>
		internal const int WM_MOUSEWHEEL = 0x20A;

		/// <summary>
		/// Posted when the user presses the right mouse button while the cursor is in the client area of a window. If the mouse is not
		/// captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646242(v=vs.85).aspx.
		/// </summary>
		internal const int WM_RBUTTONDOWN = 0x204;

		/// <summary>
		/// Posted when the user releases the right mouse button while the cursor is in the client area of a window. If the mouse is not
		/// captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646243(v=vs.85).aspx.
		/// </summary>
		internal const int WM_RBUTTONUP = 0x205;

		/// <summary>
		/// A window receives this message when the user chooses a command from the Window menu (formerly known as the system or control
		/// menu) or when the user chooses the maximize button, minimize button, restore button, or close button.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646360(v=vs.85).aspx.
		/// </summary>
		internal const int WM_SYSCOMMAND = 0x112;

		/// <summary>
		/// Posted to the window with the keyboard focus when the user presses the F10 key (which activates the menu bar) or holds down
		/// the ALT key and then presses another key. It also occurs when no window currently has the keyboard focus; in this case, the
		/// WM_SYSKEYDOWN message is sent to the active window. The window that receives the message can distinguish between these two
		/// contexts by checking the context code in the lParam parameter.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646286(v=vs.85).aspx.
		/// </summary>
		internal const int WM_SYSKEYDOWN = 0x104;

		/// <summary>
		/// Posted to the window with the keyboard focus when the user releases a key that was pressed while the ALT key was held down.
		/// It also occurs when no window currently has the keyboard focus; in this case, the WM_SYSKEYUP message is sent to the active
		/// window. The window that receives the message can distinguish between these two contexts by checking the context code in the
		/// lParam parameter.
		/// 
		/// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms646287(v=vs.85).aspx
		/// </summary>
		internal const int WM_SYSKEYUP = 0x105;

		/// <summary>
		/// Posted when the user presses the first or second X button while the cursor is in the client area of a window. If the mouse is
		/// not captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://docs.microsoft.com/de-de/windows/desktop/inputdev/wm-xbuttondown.
		/// </summary>
		internal const int WM_XBUTTONDOWN = 0x20B;

		/// <summary>
		/// Posted when the user releases the first or second X button while the cursor is in the client area of a window. If the mouse is
		/// not captured, the message is posted to the window beneath the cursor. Otherwise, the message is posted to the window that has
		/// captured the mouse.
		/// 
		/// See https://docs.microsoft.com/de-de/windows/desktop/inputdev/wm-xbuttonup.
		/// </summary>
		internal const int WM_XBUTTONUP = 0x20C;
	}
}
