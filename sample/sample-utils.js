
/**
 *  copy the content of <elementId> to the clipboard
 */
function onCopy( elementId ) {
    var data =  document.getElementById( elementId ).innerHTML
    // can we write into the clipboard ?
    navigator.permissions.query({name: "clipboard-write"}).then(result => {
        if (result.state == "granted" || result.state == "prompt") {
            navigator.clipboard.writeText(data)
            alert("public adress :\n\n" + data + "\n\nsucessfully copied to the clipboard"  )
        }
        else {
            alert("acces to the clipboard denied\n"  + result.state  )
        }
    });

}   


/**
 *  display an error in the page
 */
function showError( error, elementId ) {
    if (!elementId)
        elementId = "error" 

    // show error as html
    document.getElementById(elementId).innerHTML = "<p>" + error.message  + "</p>" ; 
    document.getElementById(elementId).hidden    = false   
}