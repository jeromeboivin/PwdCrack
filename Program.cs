using LevelDB;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PwdCrack
{
	public static class Program
	{
		private const int _batchSize = 100000;
		private static byte[][] _hashesToBruteforce;
		private static ulong counter = 0;
		private static string[] _bruteforceDictionnary = null;
		private static bool _shellOnly = false;

		static void Main(string[] args)
		{
			if (args.Length < 1)
			{
				Usage();
				return;
			}

			using (Process p = Process.GetCurrentProcess())
				p.PriorityClass = ProcessPriorityClass.BelowNormal;

			string inputPath = null;
			_shellOnly = PwdCrackSettings.Default.BruteForceShellOnly;

			if (args.Length == 1)
			{
				inputPath = args[0];
			}
			else if (args.Length == 2)
			{
				if (args[0] == "-h")
				{
					inputPath = args[1];
				}
				else if(args[0] == "-p")
				{
					Console.WriteLine(ByteArrayToString(GetHashBytes(args[1])));
				}
			}
			else if (args.Length >= 4)
			{
				if (args[0] == "-b")
				{
					// Generate brute force file
					int passwordLengthStart = Int32.Parse(args[1]);
					int passwordLengthEnd = Int32.Parse(args[2]);

					if (args.Length == 5)
					{
						if (!File.Exists(args[4]))
						{
							_bruteforceDictionnary = new string[1];
							_bruteforceDictionnary[0] = args[4];
						}
						else
						{
							string hint;
							ulong lineCount = 0;

							using (StreamReader file = new StreamReader(args[4]))
							{
								while ((hint = file.ReadLine()) != null)
								{
									if (!string.IsNullOrEmpty(hint))
									{
										lineCount++;
									}
								}
							}

							_bruteforceDictionnary = new string[lineCount];
							lineCount = 0;

							using (StreamReader file = new StreamReader(args[4]))
							{
								while ((hint = file.ReadLine()) != null)
								{
									if (!string.IsNullOrEmpty(hint))
									{
										_bruteforceDictionnary[lineCount++] = hint;
									}
								}
							}

							Console.Error.WriteLine("Bruteforce dictionary: loaded {0} passwords.", _bruteforceDictionnary.Length.ToString());
						}
					}

					if (File.Exists(args[3]))
					{
						LoadHashFile(args[3]);
					}
					else
					{
						_hashesToBruteforce = new byte[1][];
						_hashesToBruteforce[0] = StringToByteArray(args[3]);
					}

					Console.Error.WriteLine("Hashes to bruteforce: {0}", _hashesToBruteforce.Length.ToString());

					CharacterSet selectedCharacterSet;

					if (!Enum.TryParse(PwdCrackSettings.Default.BruteForceCharacterSet, true, out selectedCharacterSet))
					{
						selectedCharacterSet = CharacterSet.All;
					}

					BruteForcer bruteForcer = new BruteForcer();
					for (int passwordLength = passwordLengthStart; passwordLength <= passwordLengthEnd; passwordLength++ )
					{
						Console.Error.WriteLine($"Starting brute force with length {passwordLength}. Character set: {selectedCharacterSet}");
						if (bruteForcer.StartBruteForce(passwordLength, BruteForceRaw, selectedCharacterSet))
						{
							return;
						}

						if (bruteForcer.StartBruteForce(passwordLength, BruteForceConcat, selectedCharacterSet))
						{
							return;
						}

						if (selectedCharacterSet != CharacterSet.AlphaUpper &&
							selectedCharacterSet != CharacterSet.AlphaUpperWithNumbers &&
							selectedCharacterSet != CharacterSet.Numbers &&
							selectedCharacterSet != CharacterSet.NumbersAndCommonSymbols &&
							selectedCharacterSet != CharacterSet.NumbersAndSymbols &&
							bruteForcer.StartBruteForce(passwordLength, BruteForceUpperCase, selectedCharacterSet))
						{
							return;
						}

						if (selectedCharacterSet != CharacterSet.Numbers &&
							selectedCharacterSet != CharacterSet.NumbersAndCommonSymbols &&
							selectedCharacterSet != CharacterSet.NumbersAndSymbols && 
							bruteForcer.StartBruteForce(passwordLength, BruteForceCapitalize, selectedCharacterSet))
						{
							return;
						}
					}
				}
			}
			else
			{
				Usage();
				return;
			}

			string dbPath = PwdCrackSettings.Default.DBPath;

			if (File.Exists(inputPath))
			{
				if (args[0] == "-h")
				{
					ProcessHashFile(inputPath, dbPath);
				}
				else
				{
					ProcessFile(ref counter, inputPath, dbPath);
					Console.Error.WriteLine("End. Processed total of {0} passwords...", counter.ToString());
				}
			}
			else if (Directory.Exists(inputPath))
			{
				ProcessDirectory(ref counter, inputPath, dbPath);
				Console.Error.WriteLine("End. Processed total of {0} passwords...", counter.ToString());
			}
			else if (inputPath != null && inputPath.Length == ((512/8) * 2)) // SHA-512 hash length
			{
				byte[] hashBytes = StringToByteArray(inputPath);
				string password = GetPasswordFromHash(hashBytes, dbPath);

				if (password != null)
				{
					Console.Error.WriteLine("Found matching password: '{0}'", password);
				}
				else
				{
					Console.Error.WriteLine("No result.");
				}
			}
		}

		private static bool ArraysEqual(byte[] a1, byte[] a2)
		{
			if (a1.Length == a2.Length)
			{
				for (int i = 0; i < a1.Length; i++)
				{
					if (a1[i] != a2[i])
					{
						return false;
					}
				}
				return true;
			}
			return false;
		}

		public static bool BruteForceRaw(string passwordPattern)
		{
			if (_bruteforceDictionnary == null)
			{
				return TryPassword(passwordPattern);
			}
			else
			{
				for (int hintIdx = 0; hintIdx < _bruteforceDictionnary.Length; hintIdx++)
				{
					string currentHint = _bruteforceDictionnary[hintIdx];

					// Try raw pattern
					for (int startIndex = 0; startIndex < passwordPattern.Length; startIndex++)
					{
						string passwordStart = passwordPattern.Substring(0, startIndex);
						string passwordEnd = passwordPattern.Substring(startIndex);
						string password = passwordStart + currentHint + passwordEnd;

						if (TryPassword(password))
						{
							return true;
						}
					}
				}
			}

			return false;
		}

		public static bool BruteForceConcat(string passwordPattern)
		{
			if (!PwdCrackSettings.Default.BruteForceConcat)
			{
				return false;
			}

			if (_bruteforceDictionnary == null)
			{
				return TryPassword(passwordPattern);
			}
			else
			{
				for (int hint1Idx = 0; hint1Idx < _bruteforceDictionnary.Length; hint1Idx++)
				{
					string hint1 = _bruteforceDictionnary[hint1Idx];

					for (int hint2Idx = 0; hint2Idx < _bruteforceDictionnary.Length; hint2Idx++)
					{
						string hint2 = _bruteforceDictionnary[hint2Idx];
						string hint = string.Concat(hint1, hint2);

						// Try raw pattern
						for (int startIndex = 0; startIndex < passwordPattern.Length; startIndex++)
						{
							string passwordStart = passwordPattern.Substring(0, startIndex);
							string passwordEnd = passwordPattern.Substring(startIndex);
							string password = passwordStart + hint + passwordEnd;

							if (TryPassword(password))
							{
								return true;
							}
						}
					}
				}
			}

			return false;
		}

		public static bool BruteForceCapitalize(string passwordPattern)
		{
			if (_bruteforceDictionnary == null)
			{
				return TryPassword(passwordPattern);
			}
			else
			{
				for (int hintIdx = 0; hintIdx < _bruteforceDictionnary.Length; hintIdx++)
				{
					string currentHint = _bruteforceDictionnary[hintIdx];

					// Try capitalizing letters
					for (int letterIndex = 0; letterIndex < currentHint.Length; letterIndex++)
					{
						char[] charArray = currentHint.ToCharArray();
						charArray[letterIndex] = Char.ToUpper(charArray[letterIndex]);
						string passwordHintWithCase = new string(charArray);

						for (int startIndex = 0; startIndex < passwordPattern.Length; startIndex++)
						{
							string passwordStart = passwordPattern.Substring(0, startIndex);
							string passwordEnd = passwordPattern.Substring(startIndex);
							string password = passwordStart + passwordHintWithCase + passwordEnd;

							if (TryPassword(password))
							{
								return true;
							}
						}
					}
				}
			}

			return false;
		}

		public static bool BruteForceUpperCase(string passwordPattern)
		{
			if (_bruteforceDictionnary == null)
			{
				return TryPassword(passwordPattern);
			}
			else
			{
				for (int hintIdx = 0; hintIdx < _bruteforceDictionnary.Length; hintIdx++)
				{
					string currentHint = _bruteforceDictionnary[hintIdx];

					// Try upper case
					for (int startIndex = 0; startIndex < passwordPattern.Length; startIndex++)
					{
						string passwordStart = passwordPattern.Substring(0, startIndex);
						string passwordEnd = passwordPattern.Substring(startIndex);
						string password = passwordStart + currentHint.ToUpper() + passwordEnd;

						if (TryPassword(password))
						{
							return true;
						}
					}
				}
			}

			return false;
		}

		private static bool TryPassword(string password, bool verbose = false)
		{
			if (_shellOnly)
			{
				Console.WriteLine(password);
				return false;
			}

			if (verbose)
			{
				counter++;

				if (counter % (_batchSize * 10) == 0)
				{
					// stopwatch.Stop();
					// double rate = (stopwatch.ElapsedMilliseconds != 0) ? (((_batchSize * 10) * 1000) / stopwatch.ElapsedMilliseconds) / 1000 : 0;
					// stopwatch.Restart();

					// Console.Error.WriteLine("Trying password '{0}'... Rate: {1} kH/s.", password, rate.ToString("N0"));
					Console.Error.WriteLine("Trying password '{0}'...", password);
				}
			}

			byte[] hash = GetHashBytes(password);

			for (int hashIdx = 0; hashIdx < _hashesToBruteforce.Length; hashIdx++)
			{
				byte[] currentHash = _hashesToBruteforce[hashIdx];
				int byteIdx;

				for (byteIdx = 0; byteIdx < hash.Length; byteIdx++)
				{
					if (hash[byteIdx] != currentHash[byteIdx])
					{
						break;
					}
				}

				if (byteIdx == hash.Length)
				{
					Console.WriteLine("{0}:{1}", ByteArrayToString(hash), password);
					Console.Error.WriteLine("Found matching password: {0}:{1}", ByteArrayToString(hash), password);
				}
			}

			return _hashesToBruteforce.Length == 0;
		}

		private static void Usage()
		{
			Console.Error.WriteLine("Usage:");
			Console.Error.WriteLine("\tPwdCrack <dictionary/hash>");
			Console.Error.WriteLine("\tPwdCrack -h <hashfile>");
			Console.Error.WriteLine("Bruteforce with dictionary:");
			Console.Error.WriteLine("\tPwdCrack.exe -b <min chars> <max chars> <hashfile> <dictionary>");
			Console.Error.WriteLine("Edit <BruteForceCharacterSet> key in PwdCrack.exe.config to change character set.");
			Console.Error.WriteLine("Available values:");
			Console.Error.WriteLine("\tAll");
			Console.Error.WriteLine("\tAlphaMixedWithNumbersAndCommonSymbols");
			Console.Error.WriteLine("\tNumbers");
			Console.Error.WriteLine("\tNumbersAndSymbols");
			Console.Error.WriteLine("\tNumbersAndCommonSymbols");
			Console.Error.WriteLine("\tAlphaUpper");
			Console.Error.WriteLine("\tAlphaUpperWithNumbers");
			Console.Error.WriteLine("\tAlphaLower");
			Console.Error.WriteLine("\tAlphaLowerWithNumbers");
			Console.Error.WriteLine("\tAlphaMixed");
			Console.Error.WriteLine("\tAlphaMixedWithNumbers");
			Console.Error.WriteLine("\tCommonSymbols");
		}

		private static void ProcessDirectory(ref ulong counter, string dir, string dbPath)
		{
			try
			{
				foreach (string dictionary in Directory.GetFiles(dir))
				{
					ProcessFile(ref counter, dictionary, dbPath);
				}

				foreach (string subDir in Directory.GetDirectories(dir))
				{
					ProcessDirectory(ref counter, subDir, dbPath);
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.Message);
			}
		}

		private static string GetPasswordFromHash(byte[] hash, string dbPath)
		{
			using (DB db = DB.Open(dbPath, new Options() { CreateIfMissing = false }))
			{
				Slice passwordInDb;
				if (db.TryGet(ReadOptions.Default, hash, out passwordInDb))
				{
					return passwordInDb.ToString();
				}
			}

			return null;
		}

		public static byte[] StringToByteArray(string hex)
		{
			return Enumerable.Range(0, hex.Length)
							 .Where(x => x % 2 == 0)
							 .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
							 .ToArray();
		}

		private static void LoadHashFile(string dictionary)
		{
			string hash;
			ulong lineCount = 0;

			using (StreamReader file = new StreamReader(dictionary))
			{
				while ((hash = file.ReadLine()) != null)
				{
					if (!string.IsNullOrEmpty(hash))
					{
						lineCount++;
					}
				}
			}

			_hashesToBruteforce = new byte[lineCount][];
			lineCount = 0;

			using (StreamReader file = new StreamReader(dictionary))
			{
				while ((hash = file.ReadLine()) != null)
				{
					if (!string.IsNullOrEmpty(hash))
					{
						_hashesToBruteforce[lineCount++] = StringToByteArray(hash);
					}
				}
			}
		}

		private static void ProcessHashFile(string dictionary, string dbPath)
		{
			string hash;
			using (StreamReader file = new StreamReader(dictionary))
			{
				while ((hash = file.ReadLine()) != null)
				{
					if (!string.IsNullOrEmpty(hash))
					{
						byte[] hashBytes = StringToByteArray(hash);
						string password = GetPasswordFromHash(hashBytes, dbPath);

						if (password != null)
						{
							Console.WriteLine("{0}:{1}", hash, password);
						}
						else
						{
							Console.WriteLine(hash);
						}
					}
				}
			}
		}

		private static void ProcessFile(ref ulong counter, string dictionary, string dbPath)
		{
			Console.WriteLine("Processing file {0}...", dictionary);
			string password;

			string currentPassword = null;

			if (File.Exists(dictionary + ".current"))
			{
				currentPassword = File.ReadAllText(dictionary + ".current");
			}

			using (DB db = DB.Open(dbPath, new Options() { CreateIfMissing = true }))
			using (StreamReader file = new StreamReader(dictionary))
			{
				List<string> passwords = new List<string>();

				// Do not process already processed passwords
				if (!string.IsNullOrEmpty(currentPassword))
				{
					Console.Write("Skipping passwords until '{0}'...", currentPassword);
					do
					{
						password = file.ReadLine();
					}
					while (password != null && password != currentPassword);

					Console.WriteLine(" Done.");

					if (password != null)
					{
						passwords.Add(password);
						counter++;
					}
				}

				while ((password = file.ReadLine()) != null)
				{
					passwords.Add(password);
					counter++;

					if ((counter % _batchSize) == 0)
					{
						Stopwatch stopwatch = Stopwatch.StartNew();
						InsertPasswordsInDb(passwords, db);
						stopwatch.Stop();
						double rate = ((passwords.Count * 1000) / stopwatch.ElapsedMilliseconds);
						passwords.Clear();

						Console.WriteLine("Processed password '{0}'... Rate: {1} Hash/Sec.", password.ToString(), rate.ToString("N2"));
						File.WriteAllText(dictionary + ".current", password);
					}
				}

				// Process remaining passwords
				if (passwords.Count > 0)
				{
					InsertPasswordsInDb(passwords, db);
					passwords.Clear();
				}
			}

			if (File.Exists(dictionary + ".current"))
			{
				File.Delete(dictionary + ".current");
			}
		}

		private static void InsertPasswordsInDb(List<string> passwords, DB db)
		{
			WriteBatch batch = new WriteBatch();

			foreach (var password in passwords)
			{
				if (!string.IsNullOrEmpty(password))
				{
					byte[] hash = GetHashBytes(password);

					batch.Put(hash, password);
				}
			}

			db.Write(WriteOptions.Default, batch);
		}

		public static string ByteArrayToString(byte[] input)
		{
			return BitConverter.ToString(input).Replace("-", string.Empty).ToLowerInvariant();
		}

		public static byte[] GetHashBytes(string input)
		{
			var bytes = Encoding.Unicode.GetBytes(input);
			using (var hash = SHA512.Create())
			{
				return hash.ComputeHash(bytes);
			}
		}
	}
}
