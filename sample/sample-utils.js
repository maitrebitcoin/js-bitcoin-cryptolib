/**
 ****************************************************** 
 * @file    sample-utils.js
 * @file    common functions= for the samples
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * 
 * @license LGPL-3.0 
 ******************************************************
 */

/**
 * copy the content of an element into the clipboard - IOS conpatible version
 * @param {string} elementId ID of the dom element to be copied
 */
function onCopy(elementId) {
    var element = document.getElementById( elementId )
    // dato to copy into de clipboard
    var data    = element.innerHTML

    // hack for IOS  : create a temp input control. required for execCommand('copy') to work
    var elementEdit = document.createElement("input")
    elementEdit.contentEditable = true;
    elementEdit.readOnly  = false;
    elementEdit.value = data      
    document.body.appendChild(elementEdit)

    var range = document.createRange();
    // select the element
    range.selectNodeContents(elementEdit);  
    elementEdit.setSelectionRange(0, 999999);

  
    try {  
      //  copy to clipboard
      var successful = document.execCommand('copy', false, null);
      if(successful){
         alert("public adress :\n\n" + data + "\n\nsucessfully copied to the clipboard"  )
      }
      else {
         alert("copy to the clipboard failed\n" )
      }
  
    } catch(err) {  
        alert("copy to the clipboard failed\n"  + err.message  )
    }  
      // Remove the selections 
    window.getSelection().removeAllRanges();
    document.body.removeChild(elementEdit)
}

/**
 *  shwn an error in the html page
 * @param {Error} error the error to be displayed
 * @param {string} elementId ID if the dom element where to show the error
 */
function showError( error, elementId ) {
    if (!elementId)
        elementId = "error" 

    // show error as html
    document.getElementById(elementId).innerHTML = "<p>" + error.message  + "</p>" ; 
    document.getElementById(elementId).hidden    = false   
}