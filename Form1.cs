using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Windows.Forms;

namespace WindowsFormsApp3
{
	public partial class Form1 : Form
	{
		public Form1()
		{
			InitializeComponent();

			txtBody.Text = EnumerateCrendentials();
		}

		[DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
		static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

		[DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
		static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

		[DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
		static extern bool CredFree([In] IntPtr cred);

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		private struct CREDENTIAL
		{
			public UInt32 Flags;
			public CredentialType Type;
			public IntPtr TargetName;
			public IntPtr Comment;
			public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
			public UInt32 CredentialBlobSize;
			public IntPtr CredentialBlob;
			public UInt32 Persist;
			public UInt32 AttributeCount;
			public IntPtr Attributes;
			public IntPtr TargetAlias;
			public IntPtr UserName;
		}

		public enum CredentialType
		{
			Generic = 1,
			DomainPassword,
			DomainCertificate,
			DomainVisiblePassword,
			GenericCertificate,
			DomainExtended,
			Maximum,
			MaximumEx = Maximum + 1000,
		}
		
		public static string EnumerateCrendentials()
		{
			string output = "";
			
			int count;
			IntPtr pCredentials;
			bool ret = CredEnumerate(null, 0, out count, out pCredentials);
			if (ret)
			{
				for (int n = 0; n < count; n++)
				{
					IntPtr credentialI = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
					CREDENTIAL credential = (CREDENTIAL) Marshal.PtrToStructure(credentialI, typeof(CREDENTIAL));

					string applicationName = Marshal.PtrToStringUni(credential.TargetName);
					string userName = Marshal.PtrToStringUni(credential.UserName);
					string secret = null;
					if (credential.CredentialBlob != IntPtr.Zero)
					{
						secret = Marshal.PtrToStringUni(credential.CredentialBlob, (int)credential.CredentialBlobSize / 2);
					}

					output += string.Format("CredentialType: {0}, ApplicationName: {1}, UserName: {2}, Password: {3}", credential.Type, applicationName, userName, secret) + "\r\n";
				}
			}
			else
			{
				int lastError = Marshal.GetLastWin32Error();
				throw new Win32Exception(lastError);
			}

			return output;
		}		
	}
}
