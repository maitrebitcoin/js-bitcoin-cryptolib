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
    var data    = element.innerHTML

    var range = document.createRange();
    // select the element
    range.selectNode(element);  
    window.getSelection().addRange(range);  
  
    try {  
      // Now that we've selected the anchor text, execute the copy command  
      var successful = document.execCommand('copy', false, null);
      var msg = successful ? 'successful' : 'unsuccessful'; 
  
      if(true){
        alert("public adress :\n\n" + data + "\n\nsucessfully copied to the clipboard"  )
      }
  
    } catch(err) {  
        alert("copy to the clipboard failed\n"  + err.message  )
    }  
      // Remove the selections 
    window.getSelection().removeAllRanges();
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