using System;
using System.Linq;
using System.Threading.Tasks;

namespace PwdCrack
{
	public delegate bool HashFunc(string password);

	public enum CharacterSet
	{
		All,
		AlphaMixedWithNumbersAndCommonSymbols,
		Numbers,
		NumbersAndSymbols,
		NumbersAndCommonSymbols,
		AlphaUpper,
		AlphaUpperWithNumbers,
		AlphaLower,
		AlphaLowerWithNumbers,
		AlphaMixed,
		AlphaMixedWithNumbers,
		CommonSymbols
	}

	public class BruteForcer
	{
		#region Private variables

		/* The length of the charactersToTest Array is stored in a
		 * additional variable to increase performance  */
		private long _computedKeys = 0;
		private bool _found = false;

		/* An array containing the characters which will be used to create the brute force keys,
		 * if less characters are used (e.g. only lower case chars) the faster the password is matched  */
		private char[] _characterSetAll =
		{
			't', 'o', 'a', 'w', 'b', 'c', 'd', 's', 'f', 'm', 'r', 'h', 'i', 'y', 'e', 'g', 'l', 'n', 'p', 'u', 'j', 'k', 'q', 'v', 'x', 'z',
			'T', 'O', 'A', 'W', 'B', 'C', 'D', 'S', 'F', 'M', 'R', 'H', 'I', 'Y', 'E', 'G', 'L', 'N', 'P', 'U', 'J', 'K', 'Q', 'V', 'X', 'Z',
			'1','2','3','4','5','6','7','8','9','0',
			'!','@','#','$','%','^','&','*','(',')','-','_','+','=','~','`','[',']','{','}','|','\\',':',';','"','\'','<','>', ',', '.', '?', '/'
		};

		private char[] _characterSetAlphaMixedWithNumbersAndCommonSymbols =
		{
			't', 'o', 'a', 'w', 'b', 'c', 'd', 's', 'f', 'm', 'r', 'h', 'i', 'y', 'e', 'g', 'l', 'n', 'p', 'u', 'j', 'k', 'q', 'v', 'x', 'z',
			'T', 'O', 'A', 'W', 'B', 'C', 'D', 'S', 'F', 'M', 'R', 'H', 'I', 'Y', 'E', 'G', 'L', 'N', 'P', 'U', 'J', 'K', 'Q', 'V', 'X', 'Z',
			'1','2','3','4','5','6','7','8','9','0',
			'!','@','#','$','%','^','&','*','(',')','-','_','+','='
		};

		private char[] _characterSetNumbers =
		{
			'1','2','3','4','5','6','7','8','9','0'
		};

		private char[] _characterSetNumbersAndSymbols =
		{
			'1','2','3','4','5','6','7','8','9','0',
			'!','@','#','$','%','^','&','*','(',')','-','_','+','=','~','`','[',']','{','}','|','\\',':',';','"','\'','<','>', ',', '.', '?', '/'
		};

		private char[] _characterSetCommonSymbols =
		{
			'!','@','#','$','%','^','&','*','(',')','-','_','+','='
		};

		private char[] _characterSetNumbersAndCommonSymbols =
		{
			'1','2','3','4','5','6','7','8','9','0',
			'!','@','#','$','%','^','&','*','(',')','-','_','+','='
		};

		private char[] _characterSetAlphaUpper =
		{
			'T', 'O', 'A', 'W', 'B', 'C', 'D', 'S', 'F', 'M', 'R', 'H', 'I', 'Y', 'E', 'G', 'L', 'N', 'P', 'U', 'J', 'K', 'Q', 'V', 'X', 'Z'
		};

		private char[] _characterSetAlphaUpperWithNumbers =
		{
			'T', 'O', 'A', 'W', 'B', 'C', 'D', 'S', 'F', 'M', 'R', 'H', 'I', 'Y', 'E', 'G', 'L', 'N', 'P', 'U', 'J', 'K', 'Q', 'V', 'X', 'Z',
			'1','2','3','4','5','6','7','8','9','0'
		};

		private char[] _characterSetAlphaLower =
		{
			't', 'o', 'a', 'w', 'b', 'c', 'd', 's', 'f', 'm', 'r', 'h', 'i', 'y', 'e', 'g', 'l', 'n', 'p', 'u', 'j', 'k', 'q', 'v', 'x', 'z'
		};

		private char[] _characterSetAlphaLowerWithNumbers =
		{
			't', 'o', 'a', 'w', 'b', 'c', 'd', 's', 'f', 'm', 'r', 'h', 'i', 'y', 'e', 'g', 'l', 'n', 'p', 'u', 'j', 'k', 'q', 'v', 'x', 'z',
			'1','2','3','4','5','6','7','8','9','0'
		};

		private char[] _characterSetAlphaMixed =
		{
			't', 'o', 'a', 'w', 'b', 'c', 'd', 's', 'f', 'm', 'r', 'h', 'i', 'y', 'e', 'g', 'l', 'n', 'p', 'u', 'j', 'k', 'q', 'v', 'x', 'z',
			'T', 'O', 'A', 'W', 'B', 'C', 'D', 'S', 'F', 'M', 'R', 'H', 'I', 'Y', 'E', 'G', 'L', 'N', 'P', 'U', 'J', 'K', 'Q', 'V', 'X', 'Z'
		};

		private char[] _characterSetAlphaMixedWithNumbers =
		{
			't', 'o', 'a', 'w', 'b', 'c', 'd', 's', 'f', 'm', 'r', 'h', 'i', 'y', 'e', 'g', 'l', 'n', 'p', 'u', 'j', 'k', 'q', 'v', 'x', 'z',
			'T', 'O', 'A', 'W', 'B', 'C', 'D', 'S', 'F', 'M', 'R', 'H', 'I', 'Y', 'E', 'G', 'L', 'N', 'P', 'U', 'J', 'K', 'Q', 'V', 'X', 'Z',
			'1','2','3','4','5','6','7','8','9','0'
		};

		#endregion

		#region Private methods

		/// <summary>
		/// Starts the recursive method which will create the keys via brute force
		/// </summary>
		/// <param name="keyLength">The length of the key</param>
		public bool StartBruteForce(int keyLength, HashFunc callback, CharacterSet characterSet)
		{
			char[] selectedCharacterSet = null;

			switch (characterSet)
			{
				case CharacterSet.AlphaLower:
					selectedCharacterSet = _characterSetAlphaLower;
					break;

				case CharacterSet.AlphaLowerWithNumbers:
					selectedCharacterSet = _characterSetAlphaLowerWithNumbers;
					break;

				case CharacterSet.AlphaMixed:
					selectedCharacterSet = _characterSetAlphaMixed;
					break;

				case CharacterSet.AlphaMixedWithNumbers:
					selectedCharacterSet = _characterSetAlphaMixedWithNumbers;
					break;

				case CharacterSet.AlphaMixedWithNumbersAndCommonSymbols:
					selectedCharacterSet = _characterSetAlphaMixedWithNumbersAndCommonSymbols;
					break;

				case CharacterSet.AlphaUpper:
					selectedCharacterSet = _characterSetAlphaUpper;
					break;

				case CharacterSet.AlphaUpperWithNumbers:
					selectedCharacterSet = _characterSetAlphaUpperWithNumbers;
					break;

				case CharacterSet.Numbers:
					selectedCharacterSet = _characterSetNumbers;
					break;

				case CharacterSet.NumbersAndSymbols:
					selectedCharacterSet = _characterSetNumbersAndSymbols;
					break;

				case CharacterSet.NumbersAndCommonSymbols:
					selectedCharacterSet = _characterSetNumbersAndCommonSymbols;
					break;

				case CharacterSet.CommonSymbols:
					selectedCharacterSet = _characterSetCommonSymbols;
					break;

				case CharacterSet.All:
				default:
					selectedCharacterSet = _characterSetAll;
					break;
			}

			_found = false;

			if (keyLength > 1)
			{
				ParallelOptions options = new ParallelOptions()
				{
					MaxDegreeOfParallelism = selectedCharacterSet.Length
				};

				Parallel.For(0, selectedCharacterSet.Length, options, idx =>
				{
					if (!_found)
					{
						var keyChars = createCharArray(keyLength, selectedCharacterSet[idx]);
						// The index of the last character will be stored for slight perfomance improvement
						var indexOfLastChar = keyLength - 1;
						createNewKey(selectedCharacterSet, 1, keyChars, keyLength, indexOfLastChar, callback);
					}
				});
			}
			else
			{
				var keyChars = createCharArray(keyLength, selectedCharacterSet[0]);
				// The index of the last character will be stored for slight perfomance improvement
				var indexOfLastChar = keyLength - 1;
				createNewKey(selectedCharacterSet, 0, keyChars, keyLength, indexOfLastChar, callback);
			}

			return _found;
		}

		/// <summary>
		/// Creates a new char array of a specific length filled with the defaultChar
		/// </summary>
		/// <param name="length">The length of the array</param>
		/// <param name="defaultChar">The char with whom the array will be filled</param>
		/// <returns></returns>
		private char[] createCharArray(int length, char defaultChar)
		{
			return (from c in new char[length] select defaultChar).ToArray();
		}

		/// <summary>
		/// This is the main workhorse, it creates new keys and compares them to the password until the password
		/// is matched or all keys of the current key length have been checked
		/// </summary>
		/// <param name="currentCharPosition">The position of the char which is replaced by new characters currently</param>
		/// <param name="keyChars">The current key represented as char array</param>
		/// <param name="keyLength">The length of the key</param>
		/// <param name="indexOfLastChar">The index of the last character of the key</param>
		private void createNewKey(char[] selectedCharacterSet, int currentCharPosition, char[] keyChars, int keyLength, int indexOfLastChar, HashFunc callback)
		{
			if (_found)
			{
				return;
			}

			var nextCharPosition = currentCharPosition + 1;
			// We are looping trough the full length of our charactersToTest array
			for (int i = 0; i < selectedCharacterSet.Length; i++)
			{
				if (_found)
				{
					return;
				}

				/* The character at the currentCharPosition will be replaced by a
				 * new character from the charactersToTest array => a new key combination will be created */
				keyChars[currentCharPosition] = selectedCharacterSet[i];

				// The method calls itself recursively until all positions of the key char array have been replaced
				if (currentCharPosition < indexOfLastChar)
				{
					createNewKey(selectedCharacterSet, nextCharPosition, keyChars, keyLength, indexOfLastChar, callback);
				}
				else
				{
					// A new key has been created, remove this counter to improve performance
					_computedKeys++;

					/* The char array will be converted to a string and compared to the password. If the password
					 * is matched the loop breaks and the password is stored as result. */
					string currentPassword = new String(keyChars);

					if (_found)
					{
						return;
					}

					if (callback(currentPassword))
					{
						_found = true;
						return;
					}
				}
			}
		}

		#endregion
	}
}
