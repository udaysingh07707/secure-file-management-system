function uploadFile() {
  const file = document.getElementById("fileInput").files[0];

  if (!file) {
    alert("Please select a file");
    return;
  }

  alert("File uploaded: " + file.name);
}

function readFile() {
  alert("Opening file...");
}

function showMetadata() {
  alert("File size: 2MB\nType: PDF\nEncrypted: Yes");
}

function shareFile() {
  alert("Share link generated 🔗");
}