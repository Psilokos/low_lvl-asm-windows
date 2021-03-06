%ifndef __NASMX_UNICODE_INC__
%define __NASMX_UNICODE_INC__

%ifdef UNICODE
	%define AddAtom AddAtomW
	%define AddConsoleAlias AddConsoleAliasW
	%define AddLocalAlternateComputerName AddLocalAlternateComputerNameW
	%define AppendMenu AppendMenuW
	%define BeginUpdateResource BeginUpdateResourceW
	%define BroadcastSystemMessage BroadcastSystemMessageW
	%define BroadcastSystemMessageEx BroadcastSystemMessageExW
	%define BuildCommDCB BuildCommDCBW
	%define BuildCommDCBAndTimeouts BuildCommDCBAndTimeoutsW
	%define CallMsgFilter CallMsgFilterW
	%define CallNamedPipe CallNamedPipeW
	%define CallWindowProc CallWindowProcW
	%define ChangeDisplaySettings ChangeDisplaySettingsW
	%define ChangeDisplaySettingsEx ChangeDisplaySettingsExW
	%define ChangeMenu ChangeMenuW
	%define CharLower CharLowerW
	%define CharLowerBuff CharLowerBuffW
	%define CharNext CharNextW
	%define CharNextEx CharNextExW
	%define CharPrev CharPrevW
	%define CharPrevEx CharPrevExW
	%define CharToOem CharToOemW
	%define CharToOemBuff CharToOemBuffW
	%define CharUpper CharUpperW
	%define CharUpperBuff CharUpperBuffW
	%define CheckNameLegalDOS8Dot3 CheckNameLegalDOS8Dot3W
	%define CommConfigDialog CommConfigDialogW
	%define CopyAcceleratorTable CopyAcceleratorTableW
	%define CopyFile CopyFileW
	%define CopyFileEx CopyFileExW
	%define CreateAcceleratorTable CreateAcceleratorTableW
	%define CreateActCtx CreateActCtxW
	%define CreateDesktop CreateDesktopW
	%define CreateDialogIndirectParam CreateDialogIndirectParamW
	%define CreateDialogParam CreateDialogParamW
	%define CreateDirectory CreateDirectoryW
	%define CreateDirectoryEx CreateDirectoryExW
	%define CreateEvent CreateEventW
	%define CreateFile CreateFileW
	%define CreateFileMapping CreateFileMappingW
	%define CreateHardLink CreateHardLinkW
	%define CreateJobObject CreateJobObjectW
	%define CreateMailslot CreateMailslotW
	%define CreateMDIWindow CreateMDIWindowW
	%define CreateMutex CreateMutexW
	%define CreateNamedPipe CreateNamedPipeW
	%define CreateProcess CreateProcessW
	%define CreateSemaphore CreateSemaphoreW
	%define CreateWaitableTimer CreateWaitableTimerW
	%define CreateWindowEx CreateWindowExW
	%define CreateWindowStation CreateWindowStationW
	%define DdeCreateStringHandle DdeCreateStringHandleW
	%define DdeInitialize DdeInitializeW
	%define DdeQueryString DdeQueryStringW
	%define DefDlgProc DefDlgProcW
	%define DefineDosDevice DefineDosDeviceW
	%define DefFrameProc DefFrameProcW
	%define DefMDIChildProc DefMDIChildProcW
	%define DefWindowProc DefWindowProcW
	%define DeleteFile DeleteFileW
	%define DeleteVolumeMountPoint DeleteVolumeMountPointW
	%define DialogBoxIndirectParam DialogBoxIndirectParamW
	%define DialogBoxParam DialogBoxParamW
	%define DispatchMessage DispatchMessageW
	%define DlgDirListComboBox DlgDirListComboBoxW
	%define DlgDirSelectComboBoxEx DlgDirSelectComboBoxExW
	%define DlgDirSelectEx DlgDirSelectExW
	%define DnsHostnameToComputerName DnsHostnameToComputerNameW
	%define DrawState DrawStateW
	%define DrawText DrawTextW
	%define DrawTextEx DrawTextExW
	%define EndUpdateResource EndUpdateResourceW
	%define EnumDesktops EnumDesktopsW
	%define EnumDisplayDevices EnumDisplayDevicesW
	%define EnumDisplaySettings EnumDisplaySettingsW
	%define EnumDisplaySettingsEx EnumDisplaySettingsExW
	%define EnumProps EnumPropsW
	%define EnumPropsEx EnumPropsExW
	%define EnumResourceLanguages EnumResourceLanguagesW
	%define EnumResourceNames EnumResourceNamesW
	%define EnumResourceTypes EnumResourceTypesW
	%define EnumWindowStations EnumWindowStationsW
	%define EnumerateLocalComputerNames EnumerateLocalComputerNamesW
	%define ExpandEnvironmentStrings ExpandEnvironmentStringsW
	%define FillConsoleOutputCharacter FillConsoleOutputCharacterW
	%define FindActCtxSectionString FindActCtxSectionStringW
	%define FindAtom FindAtomW
	%define FindFirstChangeNotification FindFirstChangeNotificationW
	%define FindFirstFile FindFirstFileW
	%define FindFirstFileEx FindFirstFileExW
	%define FindFirstStream FindFirstStreamW
	%define FindFirstVolume FindFirstVolumeW
	%define FindFirstVolumeMountPoint FindFirstVolumeMountPointW
	%define FindNextFile FindNextFileW
	%define FindNextStream FindNextStreamW
	%define FindNextVolume FindNextVolumeW
	%define FindNextVolumeMountPoint FindNextVolumeMountPointW
	%define FindResource FindResourceW
	%define FindResourceEx FindResourceExW
	%define FindWindow FindWindowW
	%define FindWindowEx FindWindowExW
	%define FormatMessage FormatMessageW
	%define FreeEnvironmentStrings FreeEnvironmentStringsW
	%define GetAltTabInfo GetAltTabInfoW
	%define GetAtomName GetAtomNameW
	%define GetBinaryType GetBinaryTypeW
	%define GetClassInfo GetClassInfoW
	%define GetClassInfoEx GetClassInfoExW
	%define GetClassLong GetClassLongW
	%define GetClipboardFormatName GetClipboardFormatNameW
	%define GetCommandLine GetCommandLineW
	%define GetCompressedFileSize GetCompressedFileSizeW
	%define GetComputerName GetComputerNameW
	%define GetComputerNameEx GetComputerNameExW
	%define GetConsoleAlias GetConsoleAliasW
	%define GetConsoleAliasExes GetConsoleAliasExesW
	%define GetConsoleAliasExesLength GetConsoleAliasExesLengthW
	%define GetConsoleAliases GetConsoleAliasesW
	%define GetConsoleAliasesLength GetConsoleAliasesLengthW
	%define GetConsoleTitle GetConsoleTitleW
	%define GetCurrentDirectory GetCurrentDirectoryW
	%define GetDefaultCommConfig GetDefaultCommConfigW
	%define GetDiskFreeSpace GetDiskFreeSpaceW
	%define GetDiskFreeSpaceEx GetDiskFreeSpaceExW
	%define GetDlgItemText GetDlgItemTextW
	%define GetDllDirectory GetDllDirectoryW
	%define GetDriveType GetDriveTypeW
	%define GetEnvironmentStrings GetEnvironmentStringsW
	%define GetEnvironmentVariable GetEnvironmentVariableW
	%define GetFileAttributes GetFileAttributesW
	%define GetFileAttributesEx GetFileAttributesExW
	%define GetFirmwareEnvironmentVariable GetFirmwareEnvironmentVariableW
	%define GetFullPathName GetFullPathNameW
	%define GetKeyNameText GetKeyNameTextW
	%define GetKeyboardLayoutName GetKeyboardLayoutNameW
	%define GetLogicalDriveStrings GetLogicalDriveStringsW
	%define GetLongPathName GetLongPathNameW
	%define GetMenuItemInfo GetMenuItemInfoW
	%define GetMenuString GetMenuStringW
	%define GetMessage GetMessageW
	%define GetModuleFileName GetModuleFileNameW
	%define GetModuleHandle GetModuleHandleW
	%define GetModuleHandleEx GetModuleHandleExW
	%define GetMonitorInfo GetMonitorInfoW
	%define GetNamedPipeHandleState GetNamedPipeHandleStateW
	%define GetPrivateProfileInt GetPrivateProfileIntW
	%define GetPrivateProfileSection GetPrivateProfileSectionW
	%define GetPrivateProfileSectionNames GetPrivateProfileSectionNamesW
	%define GetPrivateProfileString GetPrivateProfileStringW
	%define GetPrivateProfileStruct GetPrivateProfileStructW
	%define GetProfileInt GetProfileIntW
	%define GetProfileSection GetProfileSectionW
	%define GetProfileString GetProfileStringW
	%define GetProp GetPropW
	%define GetRawInputDeviceInfo GetRawInputDeviceInfoW
	%define GetShortPathName GetShortPathNameW
	%define GetStartupInfo GetStartupInfoW
	%define GetSystemDirectory GetSystemDirectoryW
	%define GetSystemWindowsDirectory GetSystemWindowsDirectoryW
	%define GetSystemWow64Directory GetSystemWow64DirectoryW
	%define GetTabbedTextExtent GetTabbedTextExtentW
	%define GetTempFileName GetTempFileNameW
	%define GetTempPath GetTempPathW
	%define GetUserObjectInformation GetUserObjectInformationW
	%define GetVersionEx GetVersionExW
	%define GetVolumeInformation GetVolumeInformationW
	%define GetVolumeNameForVolumeMountPoint GetVolumeNameForVolumeMountPointW
	%define GetVolumePathName GetVolumePathNameW
	%define GetVolumePathNamesForVolumeName GetVolumePathNamesForVolumeNameW
	%define GetWindowLong GetWindowLongW
	%define GetWindowModuleFileName GetWindowModuleFileNameW
	%define GetWindowTextLength GetWindowTextLengthW
	%define GetWindowsDirectory GetWindowsDirectoryW
	%define GlobalAddAtom GlobalAddAtomW
	%define GlobalFindAtom GlobalFindAtomW
	%define GlobalGetAtomName GlobalGetAtomNameW
	%define GrayString GrayStringW
	%define IMPGetIME IMPGetIMEW
	%define IMPQueryIME IMPQueryIMEW
	%define IMPSetIME IMPSetIMEW
	%define InsertMenu InsertMenuW
	%define InsertMenuItem InsertMenuItemW
	%define IsBadStringPtr IsBadStringPtrW
	%define IsCharAlpha IsCharAlphaW
	%define IsCharAlphaNumeric IsCharAlphaNumericW
	%define IsCharLower IsCharLowerW
	%define IsCharUpper IsCharUpperW
	%define IsDialogMessage IsDialogMessageW
	%define LoadAccelerators LoadAcceleratorsW
	%define LoadBitmap LoadBitmapW
	%define LoadCursor LoadCursorW
	%define LoadCursorFromFile LoadCursorFromFileW
	%define LoadIcon LoadIconW
	%define LoadImage LoadImageW
	%define LoadKeyboardLayout LoadKeyboardLayoutW
	%define LoadLibrary LoadLibraryW
	%define LoadLibraryEx LoadLibraryExW
	%define LoadMenu LoadMenuW
	%define LoadMenuIndirect LoadMenuIndirectW
	%define LoadString LoadStringW
	%define MapVirtualKey MapVirtualKeyW
	%define MessageBox MessageBoxW
	%define MessageBoxEx MessageBoxExW
	%define MessageBoxIndirect MessageBoxIndirectW
	%define MessageBoxTimeout MessageBoxTimeoutW
	%define ModifyMenu ModifyMenuW
	%define MoveFile MoveFileW
	%define MoveFileEx MoveFileExW
	%define MoveFileWithProgress MoveFileWithProgressW
	%define NeedCurrentDirectoryForExePath NeedCurrentDirectoryForExePathW
	%define OemToChar OemToCharW
	%define OemToCharBuff OemToCharBuffW
	%define OpenDesktop OpenDesktopW
	%define OpenEvent OpenEventW
	%define OpenFileMapping OpenFileMappingW
	%define OpenJobObject OpenJobObjectW
	%define OpenMutex OpenMutexW
	%define OpenSemaphore OpenSemaphoreW
	%define OpenWaitableTimer OpenWaitableTimerW
	%define OpenWindowStation OpenWindowStationW
	%define OutputDebugString OutputDebugStringW
	%define PeekConsoleInput PeekConsoleInputW
	%define PeekMessage PeekMessageW
	%define PostMessage PostMessageW
	%define PostThreadMessage PostThreadMessageW
	%define PrivateExtractIcons PrivateExtractIconsW
	%define QueryDosDevice QueryDosDeviceW
	%define ReadConsole ReadConsoleW
	%define ReadConsoleInput ReadConsoleInputW
	%define ReadConsoleOutput ReadConsoleOutputW
	%define ReadConsoleOutputCharacter ReadConsoleOutputCharacterW
	%define RealGetWindowClass RealGetWindowClassW
	%define RegisterClass RegisterClassW
	%define RegisterClassEx RegisterClassExW
	%define RegisterClipboardFormat RegisterClipboardFormatW
	%define RegisterDeviceNotification RegisterDeviceNotificationW
	%define RegisterWindowMessage RegisterWindowMessageW
	%define RemoveDirectory RemoveDirectoryW
	%define RemoveLocalAlternateComputerName RemoveLocalAlternateComputerNameW
	%define RemoveProp RemovePropW
	%define ReplaceFile ReplaceFileW
	%define ScrollConsoleScreenBuffer ScrollConsoleScreenBufferW
	%define SearchPath SearchPathW
	%define SendDlgItemMessage SendDlgItemMessageW
	%define SendIMEMessageEx SendIMEMessageExW
	%define SendMessage SendMessageW
	%define SendMessageCallback SendMessageCallbackW
	%define SendMessageTimeout SendMessageTimeoutW
	%define SendNotifyMessage SendNotifyMessageW
	%define SetClassLong SetClassLongW
	%define SetComputerName SetComputerNameW
	%define SetComputerNameEx SetComputerNameExW
	%define SetConsoleTitle SetConsoleTitleW
	%define SetCurrentDirectory SetCurrentDirectoryW
	%define SetDefaultCommConfig SetDefaultCommConfigW
	%define SetDlgItemText SetDlgItemTextW
	%define SetDllDirectory SetDllDirectoryW
	%define SetEnvironmentStrings SetEnvironmentStringsW
	%define SetEnvironmentVariable SetEnvironmentVariableW
	%define SetFileAttributes SetFileAttributesW
	%define SetFileShortName SetFileShortNameW
	%define SetFirmwareEnvironmentVariable SetFirmwareEnvironmentVariableW
	%define SetLocalPrimaryComputerName SetLocalPrimaryComputerNameW
	%define SetMenuItemInfo SetMenuItemInfoW
	%define SetProp SetPropW
	%define SetUserObjectInformation SetUserObjectInformationW
	%define SetVolumeLabel SetVolumeLabelW
	%define SetVolumeMountPoint SetVolumeMountPointW
	%define SetWindowLong SetWindowLongW
	%define SetWindowText SetWindowTextW
	%define SetWindowsHook SetWindowsHookW
	%define SetWindowsHookEx SetWindowsHookExW
	%define SystemParametersInfo SystemParametersInfoW
	%define TabbedTextOut TabbedTextOutW
	%define TranslateAccelerator TranslateAcceleratorW
	%define UnregisterClass UnregisterClassW
	%define UpdateResource UpdateResourceW
	%define VerLanguageName VerLanguageNameW
	%define VerifyVersionInfo VerifyVersionInfoW
	%define VkKeyScan VkKeyScanW
	%define VkKeyScanEx VkKeyScanExW
	%define WaitNamedPipe WaitNamedPipeW
	%define WinHelp WinHelpW
	%define WriteConsole WriteConsoleW
	%define WriteConsoleInput WriteConsoleInputW
	%define WriteConsoleOutput WriteConsoleOutputW
	%define WriteConsoleOutputCharacter WriteConsoleOutputCharacterW
	%define WritePrivateProfileSection WritePrivateProfileSectionW
	%define WritePrivateProfileString WritePrivateProfileStringW
	%define WritePrivateProfileStruct WritePrivateProfileStructW
	%define WriteProfileSection WriteProfileSectionW
	%define WriteProfileString WriteProfileStringW
	%define lstrcat lstrcatW
	%define lstrcmp lstrcmpW
	%define lstrcmpi lstrcmpiW
	%define lstrcpy lstrcpyW
	%define lstrcpyn lstrcpynW
	%define lstrlen lstrlenW
	%define wsprintf wsprintfW
	%define wvsprintf wvsprintfW
%else
	%define AddAtom AddAtomA
	%define AddConsoleAlias AddConsoleAliasA
	%define AddLocalAlternateComputerName AddLocalAlternateComputerNameA
	%define AppendMenu AppendMenuA
	%define BeginUpdateResource BeginUpdateResourceA
	%define BroadcastSystemMessage BroadcastSystemMessageA
	%define BroadcastSystemMessageEx BroadcastSystemMessageExA
	%define BuildCommDCB BuildCommDCBA
	%define BuildCommDCBAndTimeouts BuildCommDCBAndTimeoutsA
	%define CallMsgFilter CallMsgFilterA
	%define CallNamedPipe CallNamedPipeA
	%define CallWindowProc CallWindowProcA
	%define ChangeDisplaySettings ChangeDisplaySettingsA
	%define ChangeDisplaySettingsEx ChangeDisplaySettingsExA
	%define ChangeMenu ChangeMenuA
	%define CharLower CharLowerA
	%define CharLowerBuff CharLowerBuffA
	%define CharNext CharNextA
	%define CharNextEx CharNextExA
	%define CharPrev CharPrevA
	%define CharPrevEx CharPrevExA
	%define CharToOem CharToOemA
	%define CharToOemBuff CharToOemBuffA
	%define CharUpper CharUpperA
	%define CharUpperBuff CharUpperBuffA
	%define CheckNameLegalDOS8Dot3 CheckNameLegalDOS8Dot3A
	%define CommConfigDialog CommConfigDialogA
	%define CopyAcceleratorTable CopyAcceleratorTableA
	%define CopyFile CopyFileA
	%define CopyFileEx CopyFileExA
	%define CreateAcceleratorTable CreateAcceleratorTableA
	%define CreateActCtx CreateActCtxA
	%define CreateDesktop CreateDesktopA
	%define CreateDialogIndirectParam CreateDialogIndirectParamA
	%define CreateDialogParam CreateDialogParamA
	%define CreateDirectory CreateDirectoryA
	%define CreateDirectoryEx CreateDirectoryExA
	%define CreateEvent CreateEventA
	%define CreateFile CreateFileA
	%define CreateFileMapping CreateFileMappingA
	%define CreateHardLink CreateHardLinkA
	%define CreateJobObject CreateJobObjectA
	%define CreateMailslot CreateMailslotA
	%define CreateMDIWindow CreateMDIWindowA
	%define CreateMutex CreateMutexA
	%define CreateNamedPipe CreateNamedPipeA
	%define CreateProcess CreateProcessA
	%define CreateSemaphore CreateSemaphoreA
	%define CreateWaitableTimer CreateWaitableTimerA
	%define CreateWindowEx CreateWindowExA
	%define CreateWindowStation CreateWindowStationA
	%define DdeCreateStringHandle DdeCreateStringHandleA
	%define DdeInitialize DdeInitializeA
	%define DdeQueryString DdeQueryStringA
	%define DefDlgProc DefDlgProcA
	%define DefineDosDevice DefineDosDeviceA
	%define DefFrameProc DefFrameProcA
	%define DefMDIChildProc DefMDIChildProcA
	%define DefWindowProc DefWindowProcA
	%define DeleteFile DeleteFileA
	%define DeleteVolumeMountPoint DeleteVolumeMountPointA
	%define DialogBoxIndirectParam DialogBoxIndirectParamA
	%define DialogBoxParam DialogBoxParamA
	%define DispatchMessage DispatchMessageA
	%define DlgDirListComboBox DlgDirListComboBoxA
	%define DlgDirSelectComboBoxEx DlgDirSelectComboBoxExA
	%define DlgDirSelectEx DlgDirSelectExA
	%define DnsHostnameToComputerName DnsHostnameToComputerNameA
	%define DrawState DrawStateA
	%define DrawText DrawTextA
	%define DrawTextEx DrawTextExA
	%define EnumDesktops EnumDesktopsA
	%define EnumDisplayDevices EnumDisplayDevicesA
	%define EnumDisplaySettings EnumDisplaySettingsA
	%define EnumDisplaySettingsEx EnumDisplaySettingsExA
	%define EnumProps EnumPropsA
	%define EnumPropsEx EnumPropsExA
	%define EnumResourceLanguages EnumResourceLanguagesA
	%define EnumResourceNames EnumResourceNamesA
	%define EnumResourceTypes EnumResourceTypesA
	%define EnumWindowStations EnumWindowStationsA
	%define EnumerateLocalComputerNames EnumerateLocalComputerNamesA
	%define ExpandEnvironmentStrings ExpandEnvironmentStringsA
	%define FillConsoleOutputCharacter FillConsoleOutputCharacterA
	%define FindActCtxSectionString FindActCtxSectionStringA
	%define FindAtom FindAtomA
	%define FindFirstChangeNotification FindFirstChangeNotificationA
	%define FindFirstFile FindFirstFileA
	%define FindFirstFileEx FindFirstFileExA
	%define FindFirstVolume FindFirstVolumeA
	%define FindFirstVolumeMountPoint FindFirstVolumeMountPointA
	%define FindNextFile FindNextFileA
	%define FindNextVolume FindNextVolumeA
	%define FindNextVolumeMountPoint FindNextVolumeMountPointA
	%define FindResource FindResourceA
	%define FindResourceEx FindResourceExA
	%define FindWindow FindWindowA
	%define FindWindowEx FindWindowExA
	%define FormatMessage FormatMessageA
	%define FreeEnvironmentStrings FreeEnvironmentStringsA
	%define GetAltTabInfo GetAltTabInfoA
	%define GetAtomName GetAtomNameA
	%define GetBinaryType GetBinaryTypeA
	%define GetClassInfo GetClassInfoA
	%define GetClassInfoEx GetClassInfoExA
	%define GetClassLong GetClassLongA
	%define GetClipboardFormatName GetClipboardFormatNameA
	%define GetCommandLine GetCommandLineA
	%define GetCompressedFileSize GetCompressedFileSizeA
	%define GetComputerName GetComputerNameA
	%define GetComputerNameEx GetComputerNameExA
	%define GetConsoleAlias GetConsoleAliasA
	%define GetConsoleAliasExes GetConsoleAliasExesA
	%define GetConsoleAliasExesLength GetConsoleAliasExesLengthA
	%define GetConsoleAliases GetConsoleAliasesA
	%define GetConsoleAliasesLength GetConsoleAliasesLengthA
	%define GetConsoleTitle GetConsoleTitleA
	%define GetCurrentDirectory GetCurrentDirectoryA
	%define GetDefaultCommConfig GetDefaultCommConfigA
	%define GetDiskFreeSpace GetDiskFreeSpaceA
	%define GetDiskFreeSpaceEx GetDiskFreeSpaceExA
	%define GetDlgItemText GetDlgItemTextA
	%define GetDllDirectory GetDllDirectoryA
	%define GetDriveType GetDriveTypeA
	%define GetEnvironmentStrings GetEnvironmentStringsA
	%define GetEnvironmentVariable GetEnvironmentVariableA
	%define GetFileAttributes GetFileAttributesA
	%define GetFileAttributesEx GetFileAttributesExA
	%define GetFirmwareEnvironmentVariable GetFirmwareEnvironmentVariableA
	%define GetFullPathName GetFullPathNameA
	%define GetKeyNameText GetKeyNameTextA
	%define GetKeyboardLayoutName GetKeyboardLayoutNameA
	%define GetLogicalDriveStrings GetLogicalDriveStringsA
	%define GetLongPathName GetLongPathNameA
	%define GetMenuItemInfo GetMenuItemInfoA
	%define GetMenuString GetMenuStringA
	%define GetMessage GetMessageA
	%define GetModuleFileName GetModuleFileNameA
	%define GetModuleHandle GetModuleHandleA
	%define GetModuleHandleEx GetModuleHandleExA
	%define GetMonitorInfo GetMonitorInfoA
	%define GetNamedPipeHandleState GetNamedPipeHandleStateA
	%define GetPrivateProfileInt GetPrivateProfileIntA
	%define GetPrivateProfileSection GetPrivateProfileSectionA
	%define GetPrivateProfileSectionNames GetPrivateProfileSectionNamesA
	%define GetPrivateProfileString GetPrivateProfileStringA
	%define GetPrivateProfileStruct GetPrivateProfileStructA
	%define GetProfileInt GetProfileIntA
	%define GetProfileSection GetProfileSectionA
	%define GetProfileString GetProfileStringA
	%define GetProp GetPropA
	%define GetRawInputDeviceInfo GetRawInputDeviceInfoA
	%define GetShortPathName GetShortPathNameA
	%define GetStartupInfo GetStartupInfoA
	%define GetSystemDirectory GetSystemDirectoryA
	%define GetSystemWindowsDirectory GetSystemWindowsDirectoryA
	%define GetSystemWow64Directory GetSystemWow64DirectoryA
	%define GetTabbedTextExtent GetTabbedTextExtentA
	%define GetTempFileName GetTempFileNameA
	%define GetTempPath GetTempPathA
	%define GetUserObjectInformation GetUserObjectInformationA
	%define GetVersionEx GetVersionExA
	%define GetVolumeInformation GetVolumeInformationA
	%define GetVolumeNameForVolumeMountPoint GetVolumeNameForVolumeMountPointA
	%define GetVolumePathName GetVolumePathNameA
	%define GetVolumePathNamesForVolumeName GetVolumePathNamesForVolumeNameA
	%define GetWindowLong GetWindowLongA
	%define GetWindowModuleFileName GetWindowModuleFileNameA
	%define GetWindowTextLength GetWindowTextLengthA
	%define GetWindowsDirectory GetWindowsDirectoryA
	%define GlobalAddAtom GlobalAddAtomA
	%define GlobalFindAtom GlobalFindAtomA
	%define GlobalGetAtomName GlobalGetAtomNameA
	%define GrayString GrayStringA
	%define IMPGetIME IMPGetIMEA
	%define IMPQueryIME IMPQueryIMEA
	%define IMPSetIME IMPSetIMEA
	%define InsertMenu InsertMenuA
	%define InsertMenuItem InsertMenuItemA
	%define IsBadStringPtr IsBadStringPtrA
	%define IsCharAlpha IsCharAlphaA
	%define IsCharAlphaNumeric IsCharAlphaNumericA
	%define IsCharLower IsCharLowerA
	%define IsCharUpper IsCharUpperA
	%define IsDialogMessage IsDialogMessageA
	%define LoadAccelerators LoadAcceleratorsA
	%define LoadBitmap LoadBitmapA
	%define LoadCursor LoadCursorA
	%define LoadCursorFromFile LoadCursorFromFileA
	%define LoadIcon LoadIconA
	%define LoadImage LoadImageA
	%define LoadKeyboardLayout LoadKeyboardLayoutA
	%define LoadLibrary LoadLibraryA
	%define LoadLibraryEx LoadLibraryExA
	%define LoadMenu LoadMenuA
	%define LoadMenuIndirect LoadMenuIndirectA
	%define LoadString LoadStringA
	%define MapVirtualKey MapVirtualKeyA
	%define MessageBox MessageBoxA
	%define MessageBoxEx MessageBoxExA
	%define MessageBoxIndirect MessageBoxIndirectA
	%define MessageBoxTimeout MessageBoxTimeoutA
	%define ModifyMenu ModifyMenuA
	%define MoveFile MoveFileA
	%define MoveFileEx MoveFileExA
	%define MoveFileWithProgress MoveFileWithProgressA
	%define NeedCurrentDirectoryForExePath NeedCurrentDirectoryForExePathA
	%define OemToChar OemToCharA
	%define OemToCharBuff OemToCharBuffA
	%define OpenDesktop OpenDesktopA
	%define OpenEvent OpenEventA
	%define OpenFileMapping OpenFileMappingA
	%define OpenJobObject OpenJobObjectA
	%define OpenMutex OpenMutexA
	%define OpenSemaphore OpenSemaphoreA
	%define OpenWaitableTimer OpenWaitableTimerA
	%define OpenWindowStation OpenWindowStationA
	%define OutputDebugString OutputDebugStringA
	%define PeekConsoleInput PeekConsoleInputA
	%define PeekMessage PeekMessageA
	%define PostMessage PostMessageA
	%define PostThreadMessage PostThreadMessageA
	%define PrivateExtractIcons PrivateExtractIconsA
	%define QueryDosDevice QueryDosDeviceA
	%define ReadConsole ReadConsoleA
	%define ReadConsoleInput ReadConsoleInputA
	%define ReadConsoleOutput ReadConsoleOutputA
	%define ReadConsoleOutputCharacter ReadConsoleOutputCharacterA
	%define RealGetWindowClass RealGetWindowClassA
	%define RegisterClass RegisterClassA
	%define RegisterClassEx RegisterClassExA
	%define RegisterClipboardFormat RegisterClipboardFormatA
	%define RegisterDeviceNotification RegisterDeviceNotificationA
	%define RegisterWindowMessage RegisterWindowMessageA
	%define RemoveDirectory RemoveDirectoryA
	%define RemoveLocalAlternateComputerName RemoveLocalAlternateComputerNameA
	%define RemoveProp RemovePropA
	%define ReplaceFile ReplaceFileA
	%define ScrollConsoleScreenBuffer ScrollConsoleScreenBufferA
	%define SearchPath SearchPathA
	%define SendDlgItemMessage SendDlgItemMessageA
	%define SendIMEMessageEx SendIMEMessageExA
	%define SendMessage SendMessageA
	%define SendMessageCallback SendMessageCallbackA
	%define SendMessageTimeout SendMessageTimeoutA
	%define SendNotifyMessage SendNotifyMessageA
	%define SetClassLong SetClassLongA
	%define SetComputerName SetComputerNameA
	%define SetComputerNameEx SetComputerNameExA
	%define SetConsoleTitle SetConsoleTitleA
	%define SetCurrentDirectory SetCurrentDirectoryA
	%define SetDefaultCommConfig SetDefaultCommConfigA
	%define SetDlgItemText SetDlgItemTextA
	%define SetDllDirectory SetDllDirectoryA
	%define SetEnvironmentStrings SetEnvironmentStringsA
	%define SetEnvironmentVariable SetEnvironmentVariableA
	%define SetFileAttributes SetFileAttributesA
	%define SetFileShortName SetFileShortNameA
	%define SetFirmwareEnvironmentVariable SetFirmwareEnvironmentVariableA
	%define SetLocalPrimaryComputerName SetLocalPrimaryComputerNameA
	%define SetMenuItemInfo SetMenuItemInfoA
	%define SetProp SetPropA
	%define SetUserObjectInformation SetUserObjectInformationA
	%define SetVolumeLabel SetVolumeLabelA
	%define SetVolumeMountPoint SetVolumeMountPointA
	%define SetWindowLong SetWindowLongA
	%define SetWindowText SetWindowTextA
	%define SetWindowsHook SetWindowsHookA
	%define SetWindowsHookEx SetWindowsHookExA
	%define SystemParametersInfo SystemParametersInfoA
	%define TabbedTextOut TabbedTextOutA
	%define TranslateAccelerator TranslateAcceleratorA
	%define UnregisterClass UnregisterClassA
	%define UpdateResource UpdateResourceA
	%define VerLanguageName VerLanguageNameA
	%define VerifyVersionInfo VerifyVersionInfoA
	%define VkKeyScan VkKeyScanA
	%define VkKeyScanEx VkKeyScanExA
	%define WaitNamedPipe WaitNamedPipeA
	%define WinHelp WinHelpA
	%define WriteConsole WriteConsoleA
	%define WriteConsoleInput WriteConsoleInputA
	%define WriteConsoleOutput WriteConsoleOutputA
	%define WriteConsoleOutputCharacter WriteConsoleOutputCharacterA
	%define WritePrivateProfileSection WritePrivateProfileSectionA
	%define WritePrivateProfileString WritePrivateProfileStringA
	%define WritePrivateProfileStruct WritePrivateProfileStructA
	%define WriteProfileSection WriteProfileSectionA
	%define WriteProfileString WriteProfileStringA
	%define lstrcat lstrcatA
	%define lstrcmp lstrcmpA
	%define lstrcmpi lstrcmpiA
	%define lstrcpy lstrcpyA
	%define lstrcpyn lstrcpynA
	%define lstrlen lstrlenA
	%define wsprintf wsprintfA
	%define wvsprintf wvsprintfA
%endif

%endif
