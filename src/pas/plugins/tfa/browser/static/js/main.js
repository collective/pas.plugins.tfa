/*
    Document   : main.js
    Description:
        Auxiliary scripts for `pas.plugins.tfa`.
*/

// This is called on successful login.
// It closes the modal and reloads the page.
// Any changes here should be minified (run make "build-js" from package dir)
window.tfalogin = (modal, response, state, xhr, form) => {
  if (form && form[0].action.indexOf("@@tfa") >= 0) {
    modal.options.displayInModal = false;
    modal.hide()
    window.parent.location.reload();
    return;
  }

  if (form && form[0].action.indexOf("/login") >= 0) {
    modal.options.displayInModal = false;
    modal.hide()
    window.parent.location.reload();
  }
}
