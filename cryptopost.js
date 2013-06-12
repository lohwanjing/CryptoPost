
/*
  Base code from Stanford CS255 Cryptography course, with all relevant rights. http://crypto.stanford.edu/~dabo/cs255/
  Stanford Javascript Crypto Library for AES implementation http://crypto.stanford.edu/sjcl/
  Modified by me for a more user friendly experience as well, as well as filling in the missing parts to give it full functionality.
  @author Loh Wan Jing
*/

// Strict mode makes it easier to catch errors.
// You may comment this out if you want.
// See http://ejohn.org/blog/ecmascript-5-strict-mode-json-and-more/
"use strict";

var my_username; // user signed in as
var keys = {}; // association map of keys: group -> key
var keyGenCipher;
var keyGenCounter;






// Return the encryption of the message for the given group, in the form of a string.
//
// @param {String} plainText String to encrypt.
// @param {String} group Group name.
// @return {String} Encryption of the plaintext, encoded as a string.
function Encrypt(plainText, group) {
  
   var key64 = keys[group];
   var key = sjcl.codec.base64.toBits(key64);
   var iv = GetRandomValues(4);
   var iv64 = sjcl.codec.base64.fromBits(iv);
 
   var returnData = sjcl.json.encrypt(key, plainText);

   return returnData;

}


// Return the decryption of the message for the given group, in the form of a string.
// Throws an error in case the string is not properly encrypted.
//
// @param {String} cipherText String to decrypt.
// @param {String} group Group name.
// @return {String} Decryption of the ciphertext.
function Decrypt(cipherText, group) {

   try {
   var key64 = keys[group];
   
   var key = sjcl.codec.base64.toBits(key64);
   
   var data =  sjcl.json.decrypt(key, cipherText);
   return data;
   
   }
   catch(e) {
     throw "not encrypted";
  }
}




// Generate a new key for the given group. Keys are in base64
//
// @param {String} group Group name.
function GenerateKey(group) {
  if (keyGenCipher == null) {
      var keyGenKey = GetRandomValues(8);
	  keyGenCipher = new sjcl.cipher.aes(keyGenKey);
	  keyGenCounter = GetRandomValues(4);
  }
  
  
   //first 128 bits
  //increment counter by 1, TODO should check for carry to next array, 
  
  keyGenCounter[3] = keyGenCounter[3] +1;
  var keyArray1 =  keyGenCipher.encrypt(keyGenCounter);
  
   //2nd 128 bits
  //increment counter by 1, TODO should check for carry to next array, 
  keyGenCounter[3] = keyGenCounter[3] +1;
  var keyArray2 =  keyGenCipher.encrypt(keyGenCounter);
  
  //concat to 256 bits
   var keyArray = sjcl.bitArray.concat(keyArray1, keyArray2);
   
   
  //convert to base64 for easier reading and copying
  var base64str = sjcl.codec.base64.fromBits(keyArray);
  var key = base64str;

  keys[group] = key;
  SaveKeys();
}

// Take the current group keys, and save them in encrypted form to disk.
function SaveKeys() {
  
  if (cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
  
	var key_str = JSON.stringify(keys);
	var en_keyStr = sjcl.json.encrypt(getPasswordKey(), key_str)
	cs255.localStorage.setItem('facebook-keys-' + my_username, en_keyStr);
  }
}

//generate 64 bit salt for PKDF
function generatePasswordSalt(){
	var salt = keyGenCounter = GetRandomValues(2);
	var saltStr = salt = sjcl.codec.base64.fromBits(salt);
	cs255.localStorage.setItem('facebook-dbSalt-' + my_username, saltStr);
}

//get 64 bit salt for PKDF
function getPasswordSalt(){
   var saltStr =  cs255.localStorage.getItem('facebook-dbSalt-' + my_username);
   var salt;
   if (!saltStr){
		generatePasswordSalt();
		saltStr =  cs255.localStorage.getItem('facebook-dbSalt-' + my_username); // get just created salt string
   }
   salt = sjcl.codec.base64.toBits(saltStr);
   return salt;
}

// Load the group keys from disk.
function LoadKeys() {
  keys = {}; // Reset the keys.
  if (cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
  var saved = cs255.localStorage.getItem('facebook-keys-' + my_username);
	if (saved) {
		try {
			var de_saved =  sjcl.json.decrypt(getPasswordKey(), saved);
			keys = JSON.parse(de_saved);
		}
		catch (e) {
		    sessionStorage.clear();
			customAlertRefreshPage("Cannot Decrypt Keys. Please re-enter your password and try again");
			//keys = JSON.parse(saved);
			//cs255.localStorage.setItem('facebook-active-' + my_username, false);
		}
	}
  }
}

// local storage for extension. This allows it to work (somewhat) between http://www.facebook.com and https://www.facebook.com
var cs255 = {
  localStorage: {
    setItem: function(key, value) {
      localStorage.setItem(key, value);
      var newEntries = {};
      newEntries[key] = value;
      chrome.storage.local.set(newEntries);
    },
    getItem: function(key) {
      return localStorage.getItem(key);
    },
    clear: function() {
      chrome.storage.local.clear();
    }
  }
}

if (typeof chrome.storage === "undefined") {
  var id = function() {};
  chrome.storage = {local: {get: id, set: id}};
}
else {
  // See if there are any values stored with the extension.
  chrome.storage.local.get(null, function(onDisk) {
    for (var key in onDisk) {
      localStorage.setItem(key, onDisk[key]);
    }
  });
}

// Get n 32-bit-integers entropy as an array. Defaults to 1 word
function GetRandomValues(n) {

  var entropy = new Int32Array(n);
  // This should work in WebKit.
  window.crypto.getRandomValues(entropy);

  // Typed arrays can be funky,
  // so let's convert it to a regular array for our purposes.
  var regularArray = [];
  for (var i = 0; i < entropy.length; i++) {
    regularArray.push(entropy[i]);
  }
  return regularArray;
}

// From http://aymanh.com/9-javascript-tips-you-may-not-know#Assertion
// Just in case you want an assert() function

function AssertException(message) {
  this.message = message;
}
AssertException.prototype.toString = function() {
  return 'AssertException: ' + this.message;
}

function assert(exp, message) {
  if (!exp) {
    throw new AssertException(message);
  }
}

//From Stanford CS255 base code - get facebook user name
function SetupUsernames() {
  // get who you are logged in as
  var meta = document.getElementsByClassName('navItem tinyman')[0];

  // If we can't get a username, halt execution.
  assert (typeof meta !== "undefined", "CS255 script failed. No username detected. (This is usually harmless.)");
  
  var usernameMatched = /www.facebook.com\/(.*?)ref=tn_tnmn/i.exec(meta.innerHTML);
  usernameMatched = usernameMatched[1].replace(/&amp;/, '');
  usernameMatched = usernameMatched.replace(/\?/, '');
  usernameMatched = usernameMatched.replace(/profile\.phpid=/, '');
  my_username = usernameMatched; // Update global.
}

//initialise most needed variables such as passwords, and prompts for first time users
function Initialise() {
  
  // initialise active variable if not present, which defines if extension executes
  if (!cs255.localStorage.getItem('facebook-active-' + my_username)){
	cs255.localStorage.setItem('facebook-active-' + my_username, true);
  }
 
  var initState = cs255.localStorage.getItem('facebook-initState-' + my_username);
  if (!initState || initState == 'false' || initState == 'null') {
    // user has never used facebook extension before
	//alert(my_username);
	//alert(initState);
	customAlert("Thank you for installing FacebookCrypto.\nPlease proceed to your facebook settings page to set it up.\nIf you have already setup your account, try refreshing the page.");
	cs255.localStorage.setItem('facebook-active-' + my_username, false); //disable extension until its set up properly
	//cs255.localStorage.setItem('facebook-promptState-' + my_username, 'true'); // so we won't prompt again
  }
  
  else if (initState == 'true'){ // initialised and working
    //get and store password
     getPassword();
   }
  
}
//checks if password has been entered previously and if the password is correct
function getPassword(){
	  //check if password correctly entered
   var diskKey_str =  sessionStorage.getItem('facebook-dbKey-' + my_username);
   var diskKey;
   if (diskKey_str){
      // key already present
	  //do nothing
   }
   else {
        
         while (cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
		//prompt for password
		var password = prompt("Please enter your encryption password.\nPress cancel to disable FacebookCrypto", null);
		if (password){
		   //regenerate derived key
			var params ={};
			params.salt = getPasswordSalt();
			var diskKeyData = sjcl.misc.cachedPbkdf2(password, params); 
			diskKey = diskKeyData.key;
			
			//check if key is correct
			var en_correctStr = cs255.localStorage.getItem('facebook-correct-' + my_username);
			try {
				var de_correctStr = sjcl.json.decrypt(diskKey, en_correctStr);
			
				if (de_correctStr == "Correctness Check") {
					customAlert("FacebookCrypto is now enabled"); 
					diskKey_str = sjcl.codec.base64.fromBits(diskKey);
					sessionStorage.setItem('facebook-dbKey-' + my_username, diskKey_str);
					return;
				}
				
				
				else {
					// shouldn't get here, mac correct but plaintext wrong
					alert("BUG! MAC Correct but test encryption wrong"); 
					//cs255.localStorage.setItem('facebook-active-' + my_username, false); //disable extension until its set up properly
				}
			}
			catch (e){
				// password is wrong
				customAlert("Wrong Password Entered"); 
			}
		
		}
		else {
		   //deactivate extension, user clicked cancel and did not enter a password
		   //cs255.localStorage.setItem('facebook-active-' + my_username, false); //disable extension until its set up properly
		   Deactivate();
		}
	  }
   }
}

//use PKDF to get the derived key from the password
function getPasswordKey(){
   getPassword();
   var diskKey_str =  sessionStorage.getItem('facebook-dbKey-' + my_username);
   // alert("Should Prompt for password" + diskKey_str);
   var diskKey;
   
   if (diskKey_str){
      // key already present // should be always true
	  //alert("Disk Key Generated: " + diskKey);
	  diskKey = sjcl.codec.base64.toBits(diskKey_str);
   }
   else {
		alert("BUG! "); // should not ever happen
   }
   return diskKey;
}

function getClassName(obj) {
  if (typeof obj != "object" || obj === null) return false;
  return /(\w+)\(/.exec(obj.constructor.toString())[1];
}

function hasClass(element, cls) {
  var r = new RegExp('\\b' + cls + '\\b');
  return r.test(element.className);
}

function DocChanged(e) {
   if (document.URL.match(/groups/)){
	if (!document.getElementById('active-button')) {
        AddActivateButton();
	}
   }
   if (document.URL.match(/groups/) && cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
	if (!document.getElementById('keygen-wrapper')) {
         AddKeyWrapper();
    }
   }
	//AddKeyWrapper();
   //}
  if (document.URL.match(/groups/) && cs255.localStorage.getItem('facebook-active-' + my_username) == 'true') {
    //Check for adding encrypt button for comments
    if (e.target.nodeType != 3) {
      decryptTextOfChildNodes(e.target);
      decryptTextOfChildNodes2(e.target);
      if (!hasClass(e.target, "crypto")) {
        addEncryptCommentButton(e.target);
      } else {
        return;
      }
    }

    tryAddEncryptButton();
  }
  //Check for adding keys-table
  if (document.URL.match('settings')) {
    if (!document.getElementById('cs255-keys-table') && !hasClass(e.target, "crypto")) {
      AddEncryptionTab();
      UpdateKeysTable();
	  UpdatePasswordTable();
    }
  }
}
//Decryption of posts


function decryptTextOfChildNodes(e) {
  var msgs = e.getElementsByClassName('messageBody');

  if (msgs.length > 0) {
    var msgs_array = new Array();
    for (var i = 0; i < msgs.length; ++i) {
      msgs_array[i] = msgs[i];
    }
    for (var i = 0; i < msgs_array.length; ++i) {
      DecryptMsg(msgs_array[i]);
    }
  }

}
//Decryption of comments


function decryptTextOfChildNodes2(e) {
  var msgs = e.getElementsByClassName('UFICommentContent');

  if (msgs.length > 0) {
    var msgs_array = new Array();
	var childrenArray = new Array();
    for (var i = 0; i < msgs.length; ++i) {
	  var children = msgs[i].childNodes;
		for(var j=0; j < children.length; j++) {
			if (children[j].nodeType == 1)
			childrenArray.push(children[j]);
		}
    }
	
	for (var i = 0; i < childrenArray.length; ++i) {
	  // only want greatgrandchildren
	  var grandchildren = childrenArray[i].childNodes;
		for(var j=0; j < grandchildren.length; j++) {
			if (grandchildren[j].nodeType == 1)
			msgs_array.push(grandchildren[j]);
		}
    }
	
    for (var i = 0; i < msgs_array.length; ++i) {
      DecryptMsg(msgs_array[i]);
    }
  }

}

function RegisterChangeEvents() {
  // Facebook loads posts dynamically using AJAX, so we monitor changes
  // to the HTML to discover new posts or comments.
  var doc = document.addEventListener("DOMNodeInserted", DocChanged, false);
}

function AddEncryptionTab() {

  // On the Account Settings page, show the key setups
  if (document.URL.match('settings')) {
    var div = document.getElementById('contentArea');
    if (div) {
	
	  var h2 = document.createElement('h2');
      h2.setAttribute("class", "crypto");
      h2.innerHTML = "Facebook Crypto - Key Management";
      div.appendChild(h2);

      var table = document.createElement('table');
      table.id = 'cs255-Password-table';
      table.style.borderCollapse = "collapse";
      table.setAttribute("class", "uiInfoTable crypto");
      table.setAttribute('cellpadding', 3);
      table.setAttribute('cellspacing', 1);
      table.setAttribute('border', 1);
      table.setAttribute('width', "80%");
      div.appendChild(table);
	    

	   //h2 = document.createElement('h2');
      //h2.setAttribute("class", "crypto");
      //h2.innerHTML = "Group Keys";
      //div.appendChild(h2);

      table = document.createElement('table');
      table.id = 'cs255-keys-table';
      table.style.borderCollapse = "collapse";
      table.setAttribute("class", "uiInfoTable crypto");
      table.setAttribute('cellpadding', 3);
      table.setAttribute('cellspacing', 1);
      table.setAttribute('border', 1);
      table.setAttribute('width', "80%");
      div.appendChild(table);
	  
	}
	
  }
}

//Table to allow the user to set the password for the extension
function UpdatePasswordTable() {
  var table = document.getElementById('cs255-Password-table');
  if (!table) return;
  table.innerHTML = '';

  // ugly due to events + GreaseMonkey.
  // header
  var row = document.createElement('tr');
  var th = document.createElement('th');
  if (cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
	th.innerHTML = "Facebook Crypto is enabled";
	row.appendChild(th);
	th = document.createElement('th');
	th.innerHTML = "&nbsp;";
	row.appendChild(th);
	th = document.createElement('th');
	th.innerHTML = "&nbsp;";
	row.appendChild(th);
	table.appendChild(row);
	// add generation line
	row = document.createElement('tr');

	var td = document.createElement('td');
    td.innerHTML = 'Facebook Crypto works by encrypting your Facebook Groups messages.\n'
	+ 'To start using it, please add in the Group name and click on "Generate Key" to generate a shared cryptographic key for use in the group.\n'
	+ 'If you have obtained a key from a friend, fill in the details and use "Add Key" to update the database.' ;
    row.appendChild(td);
    td = document.createElement('td');
    row.appendChild(td);
	var button = document.createElement('input');
	button.type = 'button';
	
	button.value = 'Disable';
	
	button.addEventListener("click", Deactivate, false);
	td.appendChild(button);
	row.appendChild(td);
	
	td = document.createElement('td');
    row.appendChild(td);
	button = document.createElement('input');
	button.type = 'button';
	
	button.value = 'Reset Account Data';
	
	button.addEventListener("click", ClearUserData, false);
	td.appendChild(button);
	row.appendChild(td);

	table.appendChild(row);
  }
  else {
  th.innerHTML = "Enter your Facebook Crypto Password";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "&nbsp;";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "&nbsp;";
  row.appendChild(th);
  table.appendChild(row);
  // add generation line
  row = document.createElement('tr');

	  var td = document.createElement('td');
	  td.innerHTML = '<input id="new-pass" type="password" size="30">';
	  row.appendChild(td);

	  

	td = document.createElement('td');
	var button = document.createElement('input');
	button.type = 'button';
	if (cs255.localStorage.getItem('facebook-initState-' + my_username) == null || cs255.localStorage.getItem('facebook-initState-' + my_username) == 'false' ){
		button.value = 'Set Up Main Password';
	}
	else {
		button.value = 'Enable';
	}
	button.addEventListener("click", AddDBKey, false);
	td.appendChild(button);
	row.appendChild(td);
	
	td = document.createElement('td');
    row.appendChild(td);
	button = document.createElement('input');
	button.type = 'button';
	
	button.value = 'Reset Account Data';
	
	button.addEventListener("click", ClearUserData, false);
	td.appendChild(button);
	row.appendChild(td);

	table.appendChild(row);
	}
}

//deletes all user data for the currently logged in user
function ClearUserData(){
	var r=confirm("This will delete all stored data for this user.\nDo you wish to proceed?");
		if (r==true) {
		    cs255.localStorage.setItem('facebook-initState-' + my_username, false);
		    cs255.localStorage.setItem('facebook-active-' + my_username, false);
			keys = {};
			cs255.localStorage.setItem('facebook-correct-' + my_username, null);
			cs255.localStorage.setItem('facebook-keys-' + my_username, null);
			sessionStorage.clear();
			location.reload(true);
		}
		else {
			return;
		}
	
}

//deactivates the extension
function Deactivate(){
	cs255.localStorage.setItem('facebook-active-' + my_username, false);
	sessionStorage.clear();
	LoadKeys(); //clear keys
	UpdateKeysTable();
	UpdatePasswordTable();
	
	
}

//sets keys to empty set
function resetKeys(){
	keys = {};
	SaveKeys();
	LoadKeys();
}

//sets up main password
function AddDBKey() {
	var g = document.getElementById('new-pass').value;
  
	if (g.length < 1) {
		customAlert("Please enter a password");
		return;
	}
  
	var params ={};
	params.salt = getPasswordSalt();
	var diskKeyData = sjcl.misc.cachedPbkdf2(g, params);
	var diskKey = diskKeyData.key;
	
	var diskKey_str = sjcl.codec.base64.fromBits(diskKey);
	
	//var key_str = JSON.stringify(keys);
	//var en_keyStr = 
	var en_keyStr = sjcl.json.encrypt(diskKey, "Correctness Check")
	if (cs255.localStorage.getItem('facebook-initState-' + my_username) == null || cs255.localStorage.getItem('facebook-initState-' + my_username) == 'false' ){
	
		// totally clean state
	
		cs255.localStorage.setItem('facebook-correct-' + my_username, en_keyStr);
		cs255.localStorage.setItem('facebook-initState-' + my_username, 'true'); // properly initialised
		cs255.localStorage.setItem('facebook-active-' + my_username, true); //disable extension until its set up properly
		sessionStorage.setItem('facebook-dbKey-' + my_username, diskKey_str); // save password to session to avoid reprompt;
		resetKeys();
		UpdateKeysTable();
		UpdatePasswordTable();
	}
	else {
		//check if password is correctly entered
	    var en_correctStr = cs255.localStorage.getItem('facebook-correct-' + my_username);
			try {
				var de_correctStr = sjcl.json.decrypt(diskKey, en_correctStr);
			
				if (de_correctStr == "Correctness Check") {
					//alert("Facebook Crypto Activated"); 
					diskKey_str = sjcl.codec.base64.fromBits(diskKey);
					sessionStorage.setItem('facebook-dbKey-' + my_username, diskKey_str);
					cs255.localStorage.setItem('facebook-active-' + my_username, true);
					LoadKeys();
					UpdateKeysTable();
					UpdatePasswordTable();
					return;
				}
				
				
				else {
					// shouldn't get here, mac correct but plaintext wrong
					alert("BUG! MAC Correct but test encryption wrong"); 
					return;
					//cs255.localStorage.setItem('facebook-active-' + my_username, false); //disable extension until its set up properly
				}
			}
			catch (e){
				// password is wrong
				customAlert("Wrong Password Entered"); 
				return;
			}
	}
  
  
}

//Encrypt button is added in the upper left corner


function tryAddEncryptButton(update) {

  // Check if it already exists.
  if (document.getElementById('encrypt-button')) {
    return;
  }

  var encryptWrapper = document.createElement("span");
  encryptWrapper.style.float = "right";


  var encryptLabel = document.createElement("label");
  encryptLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm");

  var encryptButton = document.createElement("input");
  encryptButton.setAttribute("value", "Encrypt");
  encryptButton.setAttribute("type", "button");
  encryptButton.setAttribute("id", "encrypt-button");
  encryptButton.setAttribute("class", "encrypt-button");
  encryptButton.addEventListener("click", DoEncrypt, false);

  encryptLabel.appendChild(encryptButton);
  encryptWrapper.appendChild(encryptLabel);

  var liParent;
  try {
    liParent = document.getElementsByName("xhpc_message")[0].parentNode;
  } catch(e) {
    return;
  }
  liParent.appendChild(encryptWrapper);

  decryptTextOfChildNodes(document);
  decryptTextOfChildNodes2(document);

}

function addEncryptCommentButton(e) {

  var commentAreas = e.getElementsByClassName('textInput UFIAddCommentInput');

  for (var j = 0; j < commentAreas.length; j++) {

    if (commentAreas[j].parentNode.parentNode.parentNode.parentNode.getElementsByClassName("encrypt-comment-button").length > 0) {
      continue;
    }

    var encryptWrapper = document.createElement("span");
    encryptWrapper.setAttribute("class", "");
    encryptWrapper.style.cssFloat = "right";
    encryptWrapper.style.cssPadding = "2px";


    var encryptLabel = document.createElement("label");
    encryptLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm crypto");

    var encryptButton = document.createElement("input");
    encryptButton.setAttribute("value", "Encrypt");
    encryptButton.setAttribute("type", "button");
    encryptButton.setAttribute("class", "encrypt-comment-button crypto");
    encryptButton.addEventListener("click", DoEncrypt, false);

    encryptLabel.appendChild(encryptButton);
    encryptWrapper.appendChild(encryptLabel);

    commentAreas[j].parentNode.parentNode.parentNode.parentNode.appendChild(encryptWrapper);
  }
}

function AddElements() {
  if (document.URL.match(/groups/) && cs255.localStorage.getItem('facebook-active-' + my_username) == 'true') {
    tryAddEncryptButton();
    addEncryptCommentButton(document);
  }
  AddEncryptionTab();
  if (document.URL.match(/groups/)){
	AddActivateButton();
	//AddKeyWrapper();
  }
  if (document.URL.match(/groups/)&& cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
	//AddActivateButton();
	AddKeyWrapper();
  }
}

function AddActivateButton(){
   // Check if it already exists.
  if (document.getElementById('active-button')) {
    return;
  }

  var activeWrapper = document.createElement("span");
  activeWrapper.style.float = "right";


  var activeLabel = document.createElement("label");
  activeLabel.setAttribute("class", "uiButton");

  var activeButton = document.createElement("input");
  if (!cs255.localStorage.getItem('facebook-active-' + my_username) ||  cs255.localStorage.getItem('facebook-active-' + my_username) == 'false'){
	activeButton.setAttribute("value", "Enable FB Crypto");
  }
  else {
	activeButton.setAttribute("value", "Disable FB Crypto");
  }
  activeButton.setAttribute("type", "button");
  activeButton.setAttribute("id", "active-button");
  activeButton.setAttribute("class", "active-button");
  activeButton.addEventListener("click", DoActive, false);

  activeLabel.appendChild(activeButton);
  activeWrapper.appendChild(activeLabel);
  
  var listItem = document.createElement("li");
  listItem.appendChild(activeWrapper);

  var liParent;
  var ulParent;
  try {
    liParent = document.getElementById("u_0_6");
	ulParent = liParent.getElementsByTagName("ul")[0];
	ulParent.appendChild(listItem);
  } catch(e) {
	//alert(e);
    return;
  }

}

function AddKeyWrapper(){
// Check if it already exists.
  if (document.getElementById('keygen-wrapper')) {
    return;
  }
  var group = CurrentGroup();
  
	//look for menu
	var menudiv = document.getElementById('pagelet_group_actions')
	var menu = getElementsByClassName(menudiv,"uiMenuInner")[0];

	//add separator
	var separator = document.createElement("li");
	separator.setAttribute("id", "keygen-wrapper");
	separator.setAttribute("class", "uiMenuSeparator");
	menu.appendChild(separator);
	
	var viewText = "View CryptoKey";
	var genText = "Generate New CryptoKey";
	var addText = "Add CryptoKey";
	
	if (group in keys){
	  addText = "Edit Existing CryptoKey";
	
	}
	
	//add keyview 
	var keyViewer = generateCustomListElement(viewText, DoKeyView);
	
	//add keygen element
	var keygen = generateCustomListElement(genText, DoKeyGen);
	//keygen.setAttribute("class", "uiMenuItem");
	//keygen.setAttribute("id", "keygen-wrapper");
	//keygen.setAttribute("data-label", "Generate New Key");
	//keygen.appendChild(generateCustomAnchor("Generate New CryptoKey", DoKeyGen));
	
	var keyAdder = generateCustomListElement(addText, DoKeyChange);
	
	menu.appendChild(separator);
	menu.appendChild(keyViewer);
	menu.appendChild(keygen);
	menu.appendChild(keyAdder);
  
}

function generateAnchor(){
   var anchor = document.createElement("a");
   anchor.setAttribute("class", "itemAnchor");
   anchor.setAttribute("role", "menuItem");
   anchor.setAttribute("tabIndex", -1);
   
   var span = document.createElement("span");
   span.setAttribute("class", "itemLabel fsm");
   span.innerHTML = "Generate Group CryptoKey";
   anchor.appendChild(span);
   span.addEventListener("click", DoKeyGen, false);
   
   return anchor;

}

function generateCustomAnchor(label, listener){
   var anchor = document.createElement("a");
   anchor.setAttribute("class", "itemAnchor");
   anchor.setAttribute("role", "menuItem");
   anchor.setAttribute("tabIndex", -1);
   
   var span = document.createElement("span");
   span.setAttribute("class", "itemLabel fsm");
   span.innerHTML = label;
   anchor.appendChild(span);
   span.addEventListener("click", listener, false);
   
   return anchor;

}

function generateCustomListElement(label, listener){
   var listEle = document.createElement("li");
	listEle.setAttribute("class", "uiMenuItem");
	//listEle.setAttribute("id", "keygen-wrapper");
	listEle.setAttribute("data-label", label);
	

   var anchor = document.createElement("a");
   anchor.setAttribute("class", "itemAnchor");
   anchor.setAttribute("role", "menuItem");
   anchor.setAttribute("tabIndex", -1);
   
   var span = document.createElement("span");
   span.setAttribute("class", "itemLabel fsm");
   span.innerHTML = label;
   anchor.appendChild(span);
   span.addEventListener("click", listener, false);
   
   listEle.appendChild(anchor);
   
   return listEle;
   return listEle;

}



/*
function AddKeyWrapper(){
   // Check if it already exists.
  if (document.getElementById('keygen-wrapper')) {
    return;
  }

  var keygenWrapper = document.createElement("span");
  keygenWrapper.style.float = "right";
  keygenWrapper.setAttribute("id", "keygen-wrapper");

  var keygenLabel = document.createElement("label");
  keygenLabel.setAttribute("class", "uiButton");
  //keygenLabel.setAttribute("style", "cursor: text;");

  var keygenButton = document.createElement("input");
  if (!cs255.localStorage.getItem('facebook-active-' + my_username) ||  cs255.localStorage.getItem('facebook-active-' + my_username) == 'false'){
	//keygenButton.setAttribute("value", "Enable FB Crypto");
  }
  else {
    //check if key already present
	var group = CurrentGroup();
	if (group in keys) {
	   var keygenButton = document.createElement("input");
	   keygenButton.setAttribute("value", "Key: (Scroll Right) " + keys[group]);
	   keygenButton.setAttribute("style", "cursor: text;");
	   //keygenButton.innerHTML = "Group Key Defined";
	   //keygenButton.setAttribute("title", keys[group]);
	   keygenButton.setAttribute("disabled", true);
	   keygenLabel.appendChild(keygenButton);
	}
	else {
	   var keygenButton = document.createElement("input");
	   keygenButton.setAttribute("value", "Generate Key");
	   //keygenButton.setAttribute("style", "cursor: text;");
	   //keygenButton.innerHTML = "Group Key Defined";
	   keygenButton.setAttribute("title", "Generate a new key for the group, all members must have the same key to view encrypted messages");
	   //keygenButton.setAttribute("disabled", true);
	   keygenButton.setAttribute("type", "button");
	keygenButton.setAttribute("id", "keygen-button");
    keygenButton.setAttribute("class", "keygen-button");
    keygenButton.addEventListener("click", DoKeyGen, false);
	   keygenLabel.appendChild(keygenButton);
	}
	
	//keygenButton.setAttribute("value", "Generate a new key for the group");
  }
  //keygenButton.setAttribute("type", "button");
  //keygenButton.setAttribute("id", "keygen-button");
  //keygenButton.setAttribute("class", "keygen-button");
  //keygenButton.addEventListener("click", DoKeyGen, false);

  //keygenLabel.appendChild(keygenButton);
  keygenWrapper.appendChild(keygenLabel);
  
  var listItem = document.createElement("li");
  listItem.appendChild(keygenWrapper);

  var liParent;
  var ulParent;
  try {
    liParent = document.getElementById("u_0_6");
	ulParent = liParent.getElementsByTagName("ul")[0];
	ulParent.appendChild(listItem);
  } catch(e) {
	//alert(e);
    return;
  }

}
*/
function DoKeyGen(){
  var group = CurrentGroup();
  if (group in keys){
	 var overRide = confirm("Key exists.\nAre you sure you want to override the existing key?", null);
	    
		if (overRide == false){
			return;
		}
  }
 
  GenerateKey(group);
  customAlertRefreshPage("Key generated for " + group + " :\n" + keys[group]);
}

function DoKeyView(){
  var group = CurrentGroup();
  if (group in keys){
	//alert(group + "'s Key :\n" + keys[group]);
	customAlert(group + "'s Key :\n" + keys[group]);
	//customAlert(group + "'s Key :\n" + keys[group]);
  }
  else {
    customAlert(group + " has no key stored. Either generate a new key or add in an existing key");
  }
}

function DoKeyChange(){
  var group = CurrentGroup();
  var promptText = "No Key Found!\nPlease enter the new key\n"
  var existingKey = (group in keys);
  if (existingKey){
	promptText = "Key already exists!\nPlease enter the new key and press Ok to override\n";
  
  }
	 var newKey = prompt(promptText, null);
		if (newKey){
		    try {
				var keyBitArray = sjcl.codec.base64.toBits(newKey);
				assert(sjcl.bitArray.bitLength(keyBitArray) == 256, "Incorrect key size");
				keys[group] = newKey;
				SaveKeys();
				if (existingKey){
					customAlertRefreshPage("Key Changed");
				}
				else {
				    customAlertRefreshPage("Key Added");
				}
				
			}
			catch (e){
				customAlert("Invalid key entered");
				return;
			}
		}
  
}

function DoActive(){
	var activeButton = document.getElementById('active-button');
	if (!activeButton) {
	//button does not exist
	alert("BUG!");
    return;
	}
	else {
		if (!cs255.localStorage.getItem('facebook-active-' + my_username) ||  cs255.localStorage.getItem('facebook-active-' + my_username) == 'false'){
		//prompt for password
			cs255.localStorage.setItem('facebook-active-' + my_username, true);
			Initialise();
		}
		else {
			Deactivate();
		}
		location.reload(true);
		
	}
}




function GenerateKeyWrapper() {
  var group = document.getElementById('gen-key-group').value;

  if (group.length < 1) {
    customAlert("You need to set a group");
    return;
  }

  GenerateKey(group);
  
  UpdateKeysTable();
}

function UpdateKeysTable() {
  var table = document.getElementById('cs255-keys-table');
  if (!table) return;
  table.innerHTML = '';
  if (cs255.localStorage.getItem('facebook-active-' + my_username) == 'true'){
  // ugly due to events + GreaseMonkey.
  // header
  var row = document.createElement('tr');
  var th = document.createElement('th');
  th.innerHTML = "Group";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "Key";
  row.appendChild(th);
  th = document.createElement('th');
  th.innerHTML = "&nbsp;";
  row.appendChild(th);
  table.appendChild(row);

  // keys
  for (var group in keys) {
    var row = document.createElement('tr');
    row.setAttribute("data-group", group);
    var td = document.createElement('td');
    td.innerHTML = group;
    row.appendChild(td);
    td = document.createElement('td');
    td.innerHTML = keys[group];
    row.appendChild(td);
    td = document.createElement('td');

    var button = document.createElement('input');
    button.type = 'button';
    button.value = 'Delete';
    button.addEventListener("click", function(event) {
      DeleteKey(event.target.parentNode.parentNode);
    }, false);
    td.appendChild(button);
    row.appendChild(td);

    table.appendChild(row);
  }

  // add friend line
  row = document.createElement('tr');

  var td = document.createElement('td');
  td.innerHTML = '<input id="new-key-group" type="text" size="8">';
  row.appendChild(td);

  td = document.createElement('td');
  td.innerHTML = '<input id="new-key-key" type="text" size="24">';
  row.appendChild(td);

  td = document.createElement('td');
  button = document.createElement('input');
  button.type = 'button';
  button.value = 'Add Key';
  button.addEventListener("click", AddKey, false);
  td.appendChild(button);
  row.appendChild(td);

  table.appendChild(row);

  // generate line
  row = document.createElement('tr');

  td = document.createElement('td');
  td.innerHTML = '<input id="gen-key-group" type="text" size="8">';
  row.appendChild(td);

  table.appendChild(row);

  td = document.createElement('td');
  td.colSpan = "2";
  button = document.createElement('input');
  button.type = 'button';
  button.value = 'Generate New Key';
  button.addEventListener("click", GenerateKeyWrapper, false);
  td.appendChild(button);
  row.appendChild(td);
  }
}

function AddKey() {
  var g = document.getElementById('new-key-group').value;
  if (g.length < 1) {
    customAlert("You need to set a group");
    return;
  }
  var k = document.getElementById('new-key-key').value;
  try {
	var keyBitArray = sjcl.codec.base64.toBits(k);
	assert(sjcl.bitArray.bitLength(keyBitArray) == 256, "Incorrect key size");
  }
  catch (e){
     customAlert("Invalid key entered");
	 return;
  }
  
  keys[g] = k;
  SaveKeys();
  UpdateKeysTable();
}

function DeleteKey(e) {
  var group = e.getAttribute("data-group");
  delete keys[group];
  SaveKeys();
  UpdateKeysTable();
}

function DoEncrypt(e) {
  // triggered by the encrypt button
  // Contents of post or comment are saved to dummy node. So updation of contens of dummy node is also required after encryption
  if (e.target.className == "encrypt-button") {
    var textHolder = document.getElementsByClassName("uiTextareaAutogrow input mentionsTextarea textInput")[0];
    var dummy = document.getElementsByName("xhpc_message")[0];
  } else {
    console.log(e.target);
    var dummy = e.target.parentNode.parentNode.parentNode.parentNode.parentNode.parentNode.getElementsByClassName("mentionsHidden")[0];
    var textHolder = e.target.parentNode.parentNode.parentNode.parentNode.getElementsByClassName("textInput mentionsTextarea")[0];
  }

  //Get the plain text
  //var vntext=textHolder.value;
  var vntext = dummy.value;

  //Ecrypt
  var vn2text = Encrypt(vntext, CurrentGroup());

  //Replace with encrypted text
  textHolder.value = vn2text;
  dummy.value = vn2text;

  textHolder.select();

}

// Currently results in a TypeError if we're not on a group page.
function CurrentGroup() {
  // Try a few DOM elements that might exist, and would contain the group name.
  var domElement = document.getElementById('groupsJumpTitle') || document.getElementById('groupsSkyNavTitleTab');
  var groupName = domElement.innerText;
  return groupName;
}

function GetMsgText(msg) {
  return msg.innerHTML;
}

function generateDimmer() {
    var dimmerdiv = document.createElement('div');
    dimmerdiv.setAttribute("id", "dimmer");
	dimmerdiv.style.position = "fixed";
    dimmerdiv.style.left = 0;
    dimmerdiv.style.top = 0;
	dimmerdiv.style.width = '100%'; 
	dimmerdiv.style.height = '100%';
	dimmerdiv.style.backgroundColor = '#000';
	dimmerdiv.style.zIndex = 1001;
	dimmerdiv.style.opacity = 0.6;
	dimmerdiv.style.display = 'none'; 

	var div = document.body;
    div.appendChild(dimmerdiv);
}


function customAlert(msg){
    customAlertGenerator(msg, HideCustomAlert);
}
function customAlertRefreshPage(msg){
    customAlertGenerator(msg, RefreshPage);
}

function customAlertGenerator(msg, buttonListener){
   if (document.getElementById('dimmer')) {
    //dimmer created
  }
  else {
   generateDimmer()
  
  }

  if (document.getElementById('customAlert')) {
    //div created
  }
  else { //create floating box
	var div = document.body;
	
	var maindiv = document.createElement('div');
    maindiv.setAttribute("id", "customAlert");
	maindiv.setAttribute("class", "_t");
	maindiv.style.position = "fixed";
    maindiv.style.left = '50%';
    maindiv.style.top = '50%';
	maindiv.style.width = '30%'; 
	maindiv.style.height = 'auto';
	maindiv.style.marginLeft = '-15%'; 
	maindiv.style.marginTop = '-100px'; 
	maindiv.style.zIndex = 1002;
	maindiv.style.backgroundColor = '#fff';
	maindiv.style.display = 'none'; 

	
    div.appendChild(maindiv);
	
	var titlediv = document.createElement('div');
    titlediv.setAttribute("id", "customAlertTitle");
	//titlediv.setAttribute("class", "uiHeaderTitle");
	titlediv.style.backgroundColor = '#6d84b4';
	titlediv.style.border ='1px solid #3b5998';
	titlediv.style.borderBottom = '0'
	titlediv.style.color = '#fff';
	titlediv.style.fontSize = '14px';
	titlediv.style.fontWeight = 'bold'
	//background-color:#6d84b4;border:1px solid #3b5998;border-bottom:0;color:#fff;font-size:14px;font-weight:bold}
	titlediv.style.display = 'inherit'; 
    titlediv.innerText = 'CryptoPost';
	maindiv.appendChild(titlediv);
	
	var msgdiv = document.createElement('div');
	msgdiv.setAttribute("class", "_13");
	msgdiv.style.display = 'inherited'; 
	msgdiv.style.borderColor = 'transparent'; 
	msgdiv.style.height = 'auto';
	msgdiv.style.marginLeft = '5%'; 
	msgdiv.style.marginRight = '5%'; 
	
    maindiv.appendChild(msgdiv);
	
	var table = document.createElement('table');
      table.id = 'customAlertTable';
      table.style.borderCollapse = "collapse";
	  table.style.borderColor = "transparent";
      table.setAttribute("class", "uiInfoTable");
      table.setAttribute('cellpadding', 3);
      table.setAttribute('cellspacing', 1);
      table.setAttribute('border', 1);
      table.setAttribute('width', "80%");
      msgdiv.appendChild(table);
	  
	var row = document.createElement('tr');

	var td = document.createElement('td');
	td.setAttribute("id", "customAlertMsgBody");
    table.appendChild(row);
    row.appendChild(td);
	
	//add button
	var buttonWrapper = document.createElement("span");
	buttonWrapper.style.float = "right";


  var buttonLabel = document.createElement("label");
  buttonLabel.setAttribute("class", "submitBtn uiButton uiButtonConfirm");

  var buttonButton = document.createElement("input");
  buttonButton.setAttribute("value", "Ok");
  buttonButton.setAttribute("type", "button");
  buttonButton.setAttribute("id", "alert-button");
  buttonButton.setAttribute("class", "alert-button");
  buttonButton.addEventListener("click", buttonListener, false);

  buttonLabel.appendChild(buttonButton);
  buttonWrapper.appendChild(buttonLabel);
  row = document.createElement('tr');
  td = document.createElement('td');
  table.appendChild(row);
    row.appendChild(td);
	td.appendChild(buttonWrapper);
  }
  var dimmer = document.getElementById('dimmer');
  var customAlert = document.getElementById('customAlert');
  var customMsgBody = document.getElementById('customAlertMsgBody');
  //edit msg
  customMsgBody.innerHTML = msg;
  //show div
  customAlert.style.display = 'block';
   dimmer.style.display = 'block';
}

function HideCustomAlert(){


     var alertDiv = document.getElementById('customAlert');
	 alertDiv.parentNode.removeChild(alertDiv);
	 
	 var dimmer = document.getElementById('dimmer');
     dimmer.style.display = 'none';
}

function RefreshPage(){


    location.reload(true);
}

function getTextFromChildren(parent, skipClass, results) {
  var children = parent.childNodes,
    item;
  var re = new RegExp("\\b" + skipClass + "\\b");
  for (var i = 0, len = children.length; i < len; i++) {
    item = children[i];
    // if text node, collect it's text
    if (item.nodeType == 3) {
      results.push(item.nodeValue);
    } else if (!item.className || !item.className.match(re)) {
      // if it has a className and it doesn't match 
      // what we're skipping, then recurse on it
      getTextFromChildren(item, skipClass, results);
    }
  }
}

function GetMsgTextForDecryption(msg) {
  try {
    var visibleDiv = msg.getElementsByClassName("text_exposed_root");
    if (visibleDiv.length) {
      var visibleDiv = document.getElementsByClassName("text_exposed_root");
      var text = [];
      getTextFromChildren(visibleDiv[0], "text_exposed_hide", text);
      var mg = text.join("");
      return mg;

    } else {
      var innerText = msg.innerText;

      // Get rid of the trailing newline, if there is one.
      if (innerText[innerText.length-1] === '\n') {
        innerText = innerText.slice(0, innerText.length-1);
      }

      return innerText;
    }

  } catch(err) {
    return msg.innerText;
  }
}

function wbr(str, num) {
  //return str.replace(RegExp("(\\w{" + num + "})(\\w)", "g"), function(all,text,char){ 
  //  return text + "<wbr>" + char; 
  //}); 
  return str.replace(RegExp("(.{" + num + "})(.)", "g"), function(all, text, char) {
    return text + "<wbr>" + char;
  });
}

function SetMsgText(msg, new_text) {
  //msg.innerHTML = wbr(new_text, 50);
  msg.innerHTML = new_text;
}

// Rudimentary attack against HTML/JAvascript injection. From mustache.js. https://github.com/janl/mustache.js/blob/master/mustache.js#L53
function escapeHtml(string) {

  var entityMap = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': '&quot;',
    "'": '&#39;',
    "/": '&#x2F;'
  };

  return String(string).replace(/[&<>"'\/]/g, function (s) {
    return entityMap[s];
  });
}

function DecryptMsg(msg) {
  // we mark the box with the class "decrypted" to prevent attempting to decrypt it multiple times.
  
  //NEW only decrypt if extension is active
  if (!/decrypted/.test(msg.className)) {
  
	//alert(msg);
    var txt = GetMsgTextForDecryption(msg);

    var displayHTML;
    try {
      var group = CurrentGroup();
      var decryptedMsg = Decrypt(txt, group);
      decryptedMsg = escapeHtml(decryptedMsg);
      displayHTML = '<font color="#00AA00">' + decryptedMsg;
    }
    catch (e) {
      displayHTML = txt;
    }

    SetMsgText(msg, displayHTML);
    msg.className += " decrypted";
  }
}
/*
function loadSJCL() {
    // Grab the head element
    var head = document.getElementsByTagName('head')[0];

    // Create a script element
    var script = document.createElement('script');

    // Set the type
    script.type = 'text/javascript';

    // Set the source file
    script.src = './sjcl.js';

    // Add the script element to the head
    head.appendChild(script);
}
*/
//Credits to Dustin Diaz
function getElementsByClassName(node,classname) {
  if (node.getElementsByClassName) { // use native implementation if available
    return node.getElementsByClassName(classname);
  } else {
    return (function getElementsByClass(searchClass,node) {
        if ( node == null )
          node = document;
        var classElements = [],
            els = node.getElementsByTagName("*"),
            elsLen = els.length,
            pattern = new RegExp("(^|\\s)"+searchClass+"(\\s|$)"), i, j;

        for (i = 0, j = 0; i < elsLen; i++) {
          if ( pattern.test(els[i].className) ) {
              classElements[j] = els[i];
              j++;
          }
        }
        return classElements;
    })(classname, node);
  }
}


 /** Javascript cryptography implementation - Stanford Javascript Crypto Library - Minified version 
    * Copyright to the authors below
    *
    * @author Emily Stark
    * @author Mike Hamburg
    * @author Dan Boneh
    */


var sjcl={cipher:{},hash:{},keyexchange:{},mode:{},misc:{},codec:{},exception:{corrupt:function(a){this.toString=function(){return"CORRUPT: "+this.message};this.message=a},invalid:function(a){this.toString=function(){return"INVALID: "+this.message};this.message=a},bug:function(a){this.toString=function(){return"BUG: "+this.message};this.message=a},notReady:function(a){this.toString=function(){return"NOT READY: "+this.message};this.message=a}}};
if(typeof module!="undefined"&&module.exports)module.exports=sjcl;
sjcl.cipher.aes=function(a){this.h[0][0][0]||this.z();var b,c,d,e,f=this.h[0][4],g=this.h[1];b=a.length;var h=1;if(b!==4&&b!==6&&b!==8)throw new sjcl.exception.invalid("invalid aes key size");this.a=[d=a.slice(0),e=[]];for(a=b;a<4*b+28;a++){c=d[a-1];if(a%b===0||b===8&&a%b===4){c=f[c>>>24]<<24^f[c>>16&255]<<16^f[c>>8&255]<<8^f[c&255];if(a%b===0){c=c<<8^c>>>24^h<<24;h=h<<1^(h>>7)*283}}d[a]=d[a-b]^c}for(b=0;a;b++,a--){c=d[b&3?a:a-4];e[b]=a<=4||b<4?c:g[0][f[c>>>24]]^g[1][f[c>>16&255]]^g[2][f[c>>8&255]]^
g[3][f[c&255]]}};
sjcl.cipher.aes.prototype={encrypt:function(a){return this.I(a,0)},decrypt:function(a){return this.I(a,1)},h:[[[],[],[],[],[]],[[],[],[],[],[]]],z:function(){var a=this.h[0],b=this.h[1],c=a[4],d=b[4],e,f,g,h=[],i=[],k,j,l,m;for(e=0;e<0x100;e++)i[(h[e]=e<<1^(e>>7)*283)^e]=e;for(f=g=0;!c[f];f^=k||1,g=i[g]||1){l=g^g<<1^g<<2^g<<3^g<<4;l=l>>8^l&255^99;c[f]=l;d[l]=f;j=h[e=h[k=h[f]]];m=j*0x1010101^e*0x10001^k*0x101^f*0x1010100;j=h[l]*0x101^l*0x1010100;for(e=0;e<4;e++){a[e][f]=j=j<<24^j>>>8;b[e][l]=m=m<<24^m>>>8}}for(e=
0;e<5;e++){a[e]=a[e].slice(0);b[e]=b[e].slice(0)}},I:function(a,b){if(a.length!==4)throw new sjcl.exception.invalid("invalid aes block size");var c=this.a[b],d=a[0]^c[0],e=a[b?3:1]^c[1],f=a[2]^c[2];a=a[b?1:3]^c[3];var g,h,i,k=c.length/4-2,j,l=4,m=[0,0,0,0];g=this.h[b];var n=g[0],o=g[1],p=g[2],q=g[3],r=g[4];for(j=0;j<k;j++){g=n[d>>>24]^o[e>>16&255]^p[f>>8&255]^q[a&255]^c[l];h=n[e>>>24]^o[f>>16&255]^p[a>>8&255]^q[d&255]^c[l+1];i=n[f>>>24]^o[a>>16&255]^p[d>>8&255]^q[e&255]^c[l+2];a=n[a>>>24]^o[d>>16&
255]^p[e>>8&255]^q[f&255]^c[l+3];l+=4;d=g;e=h;f=i}for(j=0;j<4;j++){m[b?3&-j:j]=r[d>>>24]<<24^r[e>>16&255]<<16^r[f>>8&255]<<8^r[a&255]^c[l++];g=d;d=e;e=f;f=a;a=g}return m}};
sjcl.bitArray={bitSlice:function(a,b,c){a=sjcl.bitArray.P(a.slice(b/32),32-(b&31)).slice(1);return c===undefined?a:sjcl.bitArray.clamp(a,c-b)},extract:function(a,b,c){var d=Math.floor(-b-c&31);return((b+c-1^b)&-32?a[b/32|0]<<32-d^a[b/32+1|0]>>>d:a[b/32|0]>>>d)&(1<<c)-1},concat:function(a,b){if(a.length===0||b.length===0)return a.concat(b);var c=a[a.length-1],d=sjcl.bitArray.getPartial(c);return d===32?a.concat(b):sjcl.bitArray.P(b,d,c|0,a.slice(0,a.length-1))},bitLength:function(a){var b=a.length;
if(b===0)return 0;return(b-1)*32+sjcl.bitArray.getPartial(a[b-1])},clamp:function(a,b){if(a.length*32<b)return a;a=a.slice(0,Math.ceil(b/32));var c=a.length;b&=31;if(c>0&&b)a[c-1]=sjcl.bitArray.partial(b,a[c-1]&2147483648>>b-1,1);return a},partial:function(a,b,c){if(a===32)return b;return(c?b|0:b<<32-a)+a*0x10000000000},getPartial:function(a){return Math.round(a/0x10000000000)||32},equal:function(a,b){if(sjcl.bitArray.bitLength(a)!==sjcl.bitArray.bitLength(b))return false;var c=0,d;for(d=0;d<a.length;d++)c|=
a[d]^b[d];return c===0},P:function(a,b,c,d){var e;e=0;if(d===undefined)d=[];for(;b>=32;b-=32){d.push(c);c=0}if(b===0)return d.concat(a);for(e=0;e<a.length;e++){d.push(c|a[e]>>>b);c=a[e]<<32-b}e=a.length?a[a.length-1]:0;a=sjcl.bitArray.getPartial(e);d.push(sjcl.bitArray.partial(b+a&31,b+a>32?c:d.pop(),1));return d},k:function(a,b){return[a[0]^b[0],a[1]^b[1],a[2]^b[2],a[3]^b[3]]}};
sjcl.codec.utf8String={fromBits:function(a){var b="",c=sjcl.bitArray.bitLength(a),d,e;for(d=0;d<c/8;d++){if((d&3)===0)e=a[d/4];b+=String.fromCharCode(e>>>24);e<<=8}return decodeURIComponent(escape(b))},toBits:function(a){a=unescape(encodeURIComponent(a));var b=[],c,d=0;for(c=0;c<a.length;c++){d=d<<8|a.charCodeAt(c);if((c&3)===3){b.push(d);d=0}}c&3&&b.push(sjcl.bitArray.partial(8*(c&3),d));return b}};
sjcl.codec.hex={fromBits:function(a){var b="",c;for(c=0;c<a.length;c++)b+=((a[c]|0)+0xf00000000000).toString(16).substr(4);return b.substr(0,sjcl.bitArray.bitLength(a)/4)},toBits:function(a){var b,c=[],d;a=a.replace(/\s|0x/g,"");d=a.length;a+="00000000";for(b=0;b<a.length;b+=8)c.push(parseInt(a.substr(b,8),16)^0);return sjcl.bitArray.clamp(c,d*4)}};
sjcl.codec.base64={F:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",fromBits:function(a,b,c){var d="",e=0,f=sjcl.codec.base64.F,g=0,h=sjcl.bitArray.bitLength(a);if(c)f=f.substr(0,62)+"-_";for(c=0;d.length*6<h;){d+=f.charAt((g^a[c]>>>e)>>>26);if(e<6){g=a[c]<<6-e;e+=26;c++}else{g<<=6;e-=6}}for(;d.length&3&&!b;)d+="=";return d},toBits:function(a,b){a=a.replace(/\s|=/g,"");var c=[],d=0,e=sjcl.codec.base64.F,f=0,g;if(b)e=e.substr(0,62)+"-_";for(b=0;b<a.length;b++){g=e.indexOf(a.charAt(b));
if(g<0)throw new sjcl.exception.invalid("this isn't base64!");if(d>26){d-=26;c.push(f^g>>>d);f=g<<32-d}else{d+=6;f^=g<<32-d}}d&56&&c.push(sjcl.bitArray.partial(d&56,f,1));return c}};sjcl.codec.base64url={fromBits:function(a){return sjcl.codec.base64.fromBits(a,1,1)},toBits:function(a){return sjcl.codec.base64.toBits(a,1)}};sjcl.hash.sha256=function(a){this.a[0]||this.z();if(a){this.n=a.n.slice(0);this.i=a.i.slice(0);this.e=a.e}else this.reset()};sjcl.hash.sha256.hash=function(a){return(new sjcl.hash.sha256).update(a).finalize()};
sjcl.hash.sha256.prototype={blockSize:512,reset:function(){this.n=this.N.slice(0);this.i=[];this.e=0;return this},update:function(a){if(typeof a==="string")a=sjcl.codec.utf8String.toBits(a);var b,c=this.i=sjcl.bitArray.concat(this.i,a);b=this.e;a=this.e=b+sjcl.bitArray.bitLength(a);for(b=512+b&-512;b<=a;b+=512)this.D(c.splice(0,16));return this},finalize:function(){var a,b=this.i,c=this.n;b=sjcl.bitArray.concat(b,[sjcl.bitArray.partial(1,1)]);for(a=b.length+2;a&15;a++)b.push(0);b.push(Math.floor(this.e/
4294967296));for(b.push(this.e|0);b.length;)this.D(b.splice(0,16));this.reset();return c},N:[],a:[],z:function(){function a(e){return(e-Math.floor(e))*0x100000000|0}var b=0,c=2,d;a:for(;b<64;c++){for(d=2;d*d<=c;d++)if(c%d===0)continue a;if(b<8)this.N[b]=a(Math.pow(c,0.5));this.a[b]=a(Math.pow(c,1/3));b++}},D:function(a){var b,c,d=a.slice(0),e=this.n,f=this.a,g=e[0],h=e[1],i=e[2],k=e[3],j=e[4],l=e[5],m=e[6],n=e[7];for(a=0;a<64;a++){if(a<16)b=d[a];else{b=d[a+1&15];c=d[a+14&15];b=d[a&15]=(b>>>7^b>>>18^
b>>>3^b<<25^b<<14)+(c>>>17^c>>>19^c>>>10^c<<15^c<<13)+d[a&15]+d[a+9&15]|0}b=b+n+(j>>>6^j>>>11^j>>>25^j<<26^j<<21^j<<7)+(m^j&(l^m))+f[a];n=m;m=l;l=j;j=k+b|0;k=i;i=h;h=g;g=b+(h&i^k&(h^i))+(h>>>2^h>>>13^h>>>22^h<<30^h<<19^h<<10)|0}e[0]=e[0]+g|0;e[1]=e[1]+h|0;e[2]=e[2]+i|0;e[3]=e[3]+k|0;e[4]=e[4]+j|0;e[5]=e[5]+l|0;e[6]=e[6]+m|0;e[7]=e[7]+n|0}};
sjcl.mode.ccm={name:"ccm",encrypt:function(a,b,c,d,e){var f,g=b.slice(0),h=sjcl.bitArray,i=h.bitLength(c)/8,k=h.bitLength(g)/8;e=e||64;d=d||[];if(i<7)throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");for(f=2;f<4&&k>>>8*f;f++);if(f<15-i)f=15-i;c=h.clamp(c,8*(15-f));b=sjcl.mode.ccm.H(a,b,c,d,e,f);g=sjcl.mode.ccm.J(a,g,c,b,e,f);return h.concat(g.data,g.tag)},decrypt:function(a,b,c,d,e){e=e||64;d=d||[];var f=sjcl.bitArray,g=f.bitLength(c)/8,h=f.bitLength(b),i=f.clamp(b,h-e),k=f.bitSlice(b,
h-e);h=(h-e)/8;if(g<7)throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");for(b=2;b<4&&h>>>8*b;b++);if(b<15-g)b=15-g;c=f.clamp(c,8*(15-b));i=sjcl.mode.ccm.J(a,i,c,k,e,b);a=sjcl.mode.ccm.H(a,i.data,c,d,e,b);if(!f.equal(i.tag,a))throw new sjcl.exception.corrupt("ccm: tag doesn't match");return i.data},H:function(a,b,c,d,e,f){var g=[],h=sjcl.bitArray,i=h.k;e/=8;if(e%2||e<4||e>16)throw new sjcl.exception.invalid("ccm: invalid tag length");if(d.length>0xffffffff||b.length>0xffffffff)throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");
f=[h.partial(8,(d.length?64:0)|e-2<<2|f-1)];f=h.concat(f,c);f[3]|=h.bitLength(b)/8;f=a.encrypt(f);if(d.length){c=h.bitLength(d)/8;if(c<=65279)g=[h.partial(16,c)];else if(c<=0xffffffff)g=h.concat([h.partial(16,65534)],[c]);g=h.concat(g,d);for(d=0;d<g.length;d+=4)f=a.encrypt(i(f,g.slice(d,d+4).concat([0,0,0])))}for(d=0;d<b.length;d+=4)f=a.encrypt(i(f,b.slice(d,d+4).concat([0,0,0])));return h.clamp(f,e*8)},J:function(a,b,c,d,e,f){var g,h=sjcl.bitArray;g=h.k;var i=b.length,k=h.bitLength(b);c=h.concat([h.partial(8,
f-1)],c).concat([0,0,0]).slice(0,4);d=h.bitSlice(g(d,a.encrypt(c)),0,e);if(!i)return{tag:d,data:[]};for(g=0;g<i;g+=4){c[3]++;e=a.encrypt(c);b[g]^=e[0];b[g+1]^=e[1];b[g+2]^=e[2];b[g+3]^=e[3]}return{tag:d,data:h.clamp(b,k)}}};
sjcl.mode.ocb2={name:"ocb2",encrypt:function(a,b,c,d,e,f){if(sjcl.bitArray.bitLength(c)!==128)throw new sjcl.exception.invalid("ocb iv must be 128 bits");var g,h=sjcl.mode.ocb2.B,i=sjcl.bitArray,k=i.k,j=[0,0,0,0];c=h(a.encrypt(c));var l,m=[];d=d||[];e=e||64;for(g=0;g+4<b.length;g+=4){l=b.slice(g,g+4);j=k(j,l);m=m.concat(k(c,a.encrypt(k(c,l))));c=h(c)}l=b.slice(g);b=i.bitLength(l);g=a.encrypt(k(c,[0,0,0,b]));l=i.clamp(k(l.concat([0,0,0]),g),b);j=k(j,k(l.concat([0,0,0]),g));j=a.encrypt(k(j,k(c,h(c))));
if(d.length)j=k(j,f?d:sjcl.mode.ocb2.pmac(a,d));return m.concat(i.concat(l,i.clamp(j,e)))},decrypt:function(a,b,c,d,e,f){if(sjcl.bitArray.bitLength(c)!==128)throw new sjcl.exception.invalid("ocb iv must be 128 bits");e=e||64;var g=sjcl.mode.ocb2.B,h=sjcl.bitArray,i=h.k,k=[0,0,0,0],j=g(a.encrypt(c)),l,m,n=sjcl.bitArray.bitLength(b)-e,o=[];d=d||[];for(c=0;c+4<n/32;c+=4){l=i(j,a.decrypt(i(j,b.slice(c,c+4))));k=i(k,l);o=o.concat(l);j=g(j)}m=n-c*32;l=a.encrypt(i(j,[0,0,0,m]));l=i(l,h.clamp(b.slice(c),
m).concat([0,0,0]));k=i(k,l);k=a.encrypt(i(k,i(j,g(j))));if(d.length)k=i(k,f?d:sjcl.mode.ocb2.pmac(a,d));if(!h.equal(h.clamp(k,e),h.bitSlice(b,n)))throw new sjcl.exception.corrupt("ocb: tag doesn't match");return o.concat(h.clamp(l,m))},pmac:function(a,b){var c,d=sjcl.mode.ocb2.B,e=sjcl.bitArray,f=e.k,g=[0,0,0,0],h=a.encrypt([0,0,0,0]);h=f(h,d(d(h)));for(c=0;c+4<b.length;c+=4){h=d(h);g=f(g,a.encrypt(f(h,b.slice(c,c+4))))}b=b.slice(c);if(e.bitLength(b)<128){h=f(h,d(h));b=e.concat(b,[2147483648|0,0,
0,0])}g=f(g,b);return a.encrypt(f(d(f(h,d(h))),g))},B:function(a){return[a[0]<<1^a[1]>>>31,a[1]<<1^a[2]>>>31,a[2]<<1^a[3]>>>31,a[3]<<1^(a[0]>>>31)*135]}};sjcl.misc.hmac=function(a,b){this.M=b=b||sjcl.hash.sha256;var c=[[],[]],d=b.prototype.blockSize/32;this.l=[new b,new b];if(a.length>d)a=b.hash(a);for(b=0;b<d;b++){c[0][b]=a[b]^909522486;c[1][b]=a[b]^1549556828}this.l[0].update(c[0]);this.l[1].update(c[1])};
sjcl.misc.hmac.prototype.encrypt=sjcl.misc.hmac.prototype.mac=function(a,b){a=(new this.M(this.l[0])).update(a,b).finalize();return(new this.M(this.l[1])).update(a).finalize()};
sjcl.misc.pbkdf2=function(a,b,c,d,e){c=c||1E3;if(d<0||c<0)throw sjcl.exception.invalid("invalid params to pbkdf2");if(typeof a==="string")a=sjcl.codec.utf8String.toBits(a);e=e||sjcl.misc.hmac;a=new e(a);var f,g,h,i,k=[],j=sjcl.bitArray;for(i=1;32*k.length<(d||1);i++){e=f=a.encrypt(j.concat(b,[i]));for(g=1;g<c;g++){f=a.encrypt(f);for(h=0;h<f.length;h++)e[h]^=f[h]}k=k.concat(e)}if(d)k=j.clamp(k,d);return k};
sjcl.random={randomWords:function(a,b){var c=[];b=this.isReady(b);var d;if(b===0)throw new sjcl.exception.notReady("generator isn't seeded");else b&2&&this.U(!(b&1));for(b=0;b<a;b+=4){(b+1)%0x10000===0&&this.L();d=this.w();c.push(d[0],d[1],d[2],d[3])}this.L();return c.slice(0,a)},setDefaultParanoia:function(a){this.t=a},addEntropy:function(a,b,c){c=c||"user";var d,e,f=(new Date).valueOf(),g=this.q[c],h=this.isReady(),i=0;d=this.G[c];if(d===undefined)d=this.G[c]=this.R++;if(g===undefined)g=this.q[c]=
0;this.q[c]=(this.q[c]+1)%this.b.length;switch(typeof a){case "number":if(b===undefined)b=1;this.b[g].update([d,this.u++,1,b,f,1,a|0]);break;case "object":c=Object.prototype.toString.call(a);if(c==="[object Uint32Array]"){e=[];for(c=0;c<a.length;c++)e.push(a[c]);a=e}else{if(c!=="[object Array]")i=1;for(c=0;c<a.length&&!i;c++)if(typeof a[c]!="number")i=1}if(!i){if(b===undefined)for(c=b=0;c<a.length;c++)for(e=a[c];e>0;){b++;e>>>=1}this.b[g].update([d,this.u++,2,b,f,a.length].concat(a))}break;case "string":if(b===
undefined)b=a.length;this.b[g].update([d,this.u++,3,b,f,a.length]);this.b[g].update(a);break;default:i=1}if(i)throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");this.j[g]+=b;this.f+=b;if(h===0){this.isReady()!==0&&this.K("seeded",Math.max(this.g,this.f));this.K("progress",this.getProgress())}},isReady:function(a){a=this.C[a!==undefined?a:this.t];return this.g&&this.g>=a?this.j[0]>80&&(new Date).valueOf()>this.O?3:1:this.f>=a?2:0},getProgress:function(a){a=
this.C[a?a:this.t];return this.g>=a?1:this.f>a?1:this.f/a},startCollectors:function(){if(!this.m){if(window.addEventListener){window.addEventListener("load",this.o,false);window.addEventListener("mousemove",this.p,false)}else if(document.attachEvent){document.attachEvent("onload",this.o);document.attachEvent("onmousemove",this.p)}else throw new sjcl.exception.bug("can't attach event");this.m=true}},stopCollectors:function(){if(this.m){if(window.removeEventListener){window.removeEventListener("load",
this.o,false);window.removeEventListener("mousemove",this.p,false)}else if(window.detachEvent){window.detachEvent("onload",this.o);window.detachEvent("onmousemove",this.p)}this.m=false}},addEventListener:function(a,b){this.r[a][this.Q++]=b},removeEventListener:function(a,b){var c;a=this.r[a];var d=[];for(c in a)a.hasOwnProperty(c)&&a[c]===b&&d.push(c);for(b=0;b<d.length;b++){c=d[b];delete a[c]}},b:[new sjcl.hash.sha256],j:[0],A:0,q:{},u:0,G:{},R:0,g:0,f:0,O:0,a:[0,0,0,0,0,0,0,0],d:[0,0,0,0],s:undefined,
t:6,m:false,r:{progress:{},seeded:{}},Q:0,C:[0,48,64,96,128,192,0x100,384,512,768,1024],w:function(){for(var a=0;a<4;a++){this.d[a]=this.d[a]+1|0;if(this.d[a])break}return this.s.encrypt(this.d)},L:function(){this.a=this.w().concat(this.w());this.s=new sjcl.cipher.aes(this.a)},T:function(a){this.a=sjcl.hash.sha256.hash(this.a.concat(a));this.s=new sjcl.cipher.aes(this.a);for(a=0;a<4;a++){this.d[a]=this.d[a]+1|0;if(this.d[a])break}},U:function(a){var b=[],c=0,d;this.O=b[0]=(new Date).valueOf()+3E4;for(d=
0;d<16;d++)b.push(Math.random()*0x100000000|0);for(d=0;d<this.b.length;d++){b=b.concat(this.b[d].finalize());c+=this.j[d];this.j[d]=0;if(!a&&this.A&1<<d)break}if(this.A>=1<<this.b.length){this.b.push(new sjcl.hash.sha256);this.j.push(0)}this.f-=c;if(c>this.g)this.g=c;this.A++;this.T(b)},p:function(a){sjcl.random.addEntropy([a.x||a.clientX||a.offsetX,a.y||a.clientY||a.offsetY],2,"mouse")},o:function(){sjcl.random.addEntropy((new Date).valueOf(),2,"loadtime")},K:function(a,b){var c;a=sjcl.random.r[a];
var d=[];for(c in a)a.hasOwnProperty(c)&&d.push(a[c]);for(c=0;c<d.length;c++)d[c](b)}};try{var s=new Uint32Array(32);crypto.getRandomValues(s);sjcl.random.addEntropy(s,1024,"crypto['getRandomValues']")}catch(t){}
sjcl.json={defaults:{v:1,iter:1E3,ks:128,ts:64,mode:"ccm",adata:"",cipher:"aes"},encrypt:function(a,b,c,d){c=c||{};d=d||{};var e=sjcl.json,f=e.c({iv:sjcl.random.randomWords(4,0)},e.defaults),g;e.c(f,c);c=f.adata;if(typeof f.salt==="string")f.salt=sjcl.codec.base64.toBits(f.salt);if(typeof f.iv==="string")f.iv=sjcl.codec.base64.toBits(f.iv);if(!sjcl.mode[f.mode]||!sjcl.cipher[f.cipher]||typeof a==="string"&&f.iter<=100||f.ts!==64&&f.ts!==96&&f.ts!==128||f.ks!==128&&f.ks!==192&&f.ks!==0x100||f.iv.length<
2||f.iv.length>4)throw new sjcl.exception.invalid("json encrypt: invalid parameters");if(typeof a==="string"){g=sjcl.misc.cachedPbkdf2(a,f);a=g.key.slice(0,f.ks/32);f.salt=g.salt}if(typeof b==="string")b=sjcl.codec.utf8String.toBits(b);if(typeof c==="string")c=sjcl.codec.utf8String.toBits(c);g=new sjcl.cipher[f.cipher](a);e.c(d,f);d.key=a;f.ct=sjcl.mode[f.mode].encrypt(g,b,f.iv,c,f.ts);return e.encode(f)},decrypt:function(a,b,c,d){c=c||{};d=d||{};var e=sjcl.json;b=e.c(e.c(e.c({},e.defaults),e.decode(b)),
c,true);var f;c=b.adata;if(typeof b.salt==="string")b.salt=sjcl.codec.base64.toBits(b.salt);if(typeof b.iv==="string")b.iv=sjcl.codec.base64.toBits(b.iv);if(!sjcl.mode[b.mode]||!sjcl.cipher[b.cipher]||typeof a==="string"&&b.iter<=100||b.ts!==64&&b.ts!==96&&b.ts!==128||b.ks!==128&&b.ks!==192&&b.ks!==0x100||!b.iv||b.iv.length<2||b.iv.length>4)throw new sjcl.exception.invalid("json decrypt: invalid parameters");if(typeof a==="string"){f=sjcl.misc.cachedPbkdf2(a,b);a=f.key.slice(0,b.ks/32);b.salt=f.salt}if(typeof c===
"string")c=sjcl.codec.utf8String.toBits(c);f=new sjcl.cipher[b.cipher](a);c=sjcl.mode[b.mode].decrypt(f,b.ct,b.iv,c,b.ts);e.c(d,b);d.key=a;return sjcl.codec.utf8String.fromBits(c)},encode:function(a){var b,c="{",d="";for(b in a)if(a.hasOwnProperty(b)){if(!b.match(/^[a-z0-9]+$/i))throw new sjcl.exception.invalid("json encode: invalid property name");c+=d+'"'+b+'":';d=",";switch(typeof a[b]){case "number":case "boolean":c+=a[b];break;case "string":c+='"'+escape(a[b])+'"';break;case "object":c+='"'+
sjcl.codec.base64.fromBits(a[b],1)+'"';break;default:throw new sjcl.exception.bug("json encode: unsupported type");}}return c+"}"},decode:function(a){a=a.replace(/\s/g,"");if(!a.match(/^\{.*\}$/))throw new sjcl.exception.invalid("json decode: this isn't json!");a=a.replace(/^\{|\}$/g,"").split(/,/);var b={},c,d;for(c=0;c<a.length;c++){if(!(d=a[c].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i)))throw new sjcl.exception.invalid("json decode: this isn't json!");b[d[2]]=
d[3]?parseInt(d[3],10):d[2].match(/^(ct|salt|iv)$/)?sjcl.codec.base64.toBits(d[4]):unescape(d[4])}return b},c:function(a,b,c){if(a===undefined)a={};if(b===undefined)return a;var d;for(d in b)if(b.hasOwnProperty(d)){if(c&&a[d]!==undefined&&a[d]!==b[d])throw new sjcl.exception.invalid("required parameter overridden");a[d]=b[d]}return a},W:function(a,b){var c={},d;for(d in a)if(a.hasOwnProperty(d)&&a[d]!==b[d])c[d]=a[d];return c},V:function(a,b){var c={},d;for(d=0;d<b.length;d++)if(a[b[d]]!==undefined)c[b[d]]=
a[b[d]];return c}};sjcl.encrypt=sjcl.json.encrypt;sjcl.decrypt=sjcl.json.decrypt;sjcl.misc.S={};sjcl.misc.cachedPbkdf2=function(a,b){var c=sjcl.misc.S,d;b=b||{};d=b.iter||1E3;c=c[a]=c[a]||{};d=c[d]=c[d]||{firstSalt:b.salt&&b.salt.length?b.salt.slice(0):sjcl.random.randomWords(2,0)};c=b.salt===undefined?d.firstSalt:b.salt;d[c]=d[c]||sjcl.misc.pbkdf2(a,c,b.iter);return{key:d[c].slice(0),salt:c.slice(0)}};



// This is the initialization of the content script

SetupUsernames();
//loadSJCL();
Initialise();
LoadKeys();
AddElements();
UpdateKeysTable();
UpdatePasswordTable();
RegisterChangeEvents();

console.log("CS255 script finished loading.");

// Stub for phantom.js (http://phantomjs.org/)
if (typeof phantom !== "undefined") {
  console.log("Hello! You're running in phantom.js.");
  // Add any function calls you want to run.
  phantom.exit();
}
