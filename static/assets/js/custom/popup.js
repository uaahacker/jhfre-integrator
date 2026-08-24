// Success Popup
function showSuccessPopup(message = "Form has been successfully submitted!") {
    Swal.fire({
        icon: 'success',
        title: 'Success',
        text: message,
        confirmButtonText: 'Ok, got it!',
        customClass: {
            confirmButton: 'btn btn-primary'
        }
    });
}

// Error Popup
function showErrorPopup(message = "An error occurred. Please try again.") {
    Swal.fire({
        icon: 'error',
        title: 'Error',
        text: message,
        confirmButtonText: 'Ok, got it!',
        customClass: {
            confirmButton: 'btn btn-primary'
        }
    });
}

// Warning Popup with Confirmation
function showWarningPopup(message = "Are you sure you would like to cancel?", onConfirm, onCancel) {
    Swal.fire({
        icon: 'warning',
        title: 'Warning',
        text: message,
        showCancelButton: true,
        confirmButtonText: 'Yes, cancel it!',
        cancelButtonText: 'No, return',
        customClass: {
            confirmButton: 'btn btn-primary',
            cancelButton: 'btn btn-active-light'
        }
    }).then((result) => {
        if (result.isConfirmed && onConfirm) {
            onConfirm();
        } else if (result.isDismissed && onCancel) {
            onCancel();
        }
    });
}

// Delete Confirmation Popup
function showDeletePopup(message = "Are you sure you want to delete this item?", onConfirm, onCancel) {
    Swal.fire({
        icon: 'warning',
        title: 'Delete Confirmation',
        text: message,
        showCancelButton: true,
        confirmButtonText: 'Yes, delete it!',
        cancelButtonText: 'No, cancel',
        customClass: {
            confirmButton: 'btn btn-danger',
            cancelButton: 'btn btn-active-light'
        }
    }).then((result) => {
        if (result.isConfirmed && typeof onConfirm === 'function') {
            onConfirm(); // Execute onConfirm callback
        } else if (result.dismiss === Swal.DismissReason.cancel && typeof onCancel === 'function') {
            onCancel(); // Execute onCancel callback
        }
    });
}


