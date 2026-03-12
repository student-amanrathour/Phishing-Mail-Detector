document.getElementById("saveBtn").addEventListener("click",() => {
  const key = document.getElementById("apiKey").value.trim();

  if(!key){
    document.getElementById("status").innerText = "!! Please enter a key.";
    return;
  }

  chrome.storage.local.set({VT_API_KEY: key}, () => {
    document.getElementById("status").innerText = "API Saved Successfully";
    setTimeout(() => {document.getElementById("status").innerText = "";}, 3000);
  });
});
