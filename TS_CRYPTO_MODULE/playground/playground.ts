import { KeyManager, HybridEncryption } from '../src/hybrid_crypto_module';

const keyManager = new KeyManager();
const cryptoSvc = new HybridEncryption();

const owner = await keyManager.generate_key_pair();
const user1Keys = await keyManager.generate_key_pair(); // Alice
const user2Keys = await keyManager.generate_key_pair(); // Bob


// --- Utilidades de Archivos ---

const downloadFile = (data: BlobPart, fileName: string, type: string): void => {
  const blob = new Blob([data], { type });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');

  link.href = url;
  link.download = fileName;

  // Required for Firefox
  document.body.appendChild(link);

  try {
    link.click();
  } finally {
    document.body.removeChild(link);
    // Delay revocation to ensure download has started
    setTimeout(() => window.URL.revokeObjectURL(url), 100);
  }
};

const readFileAsArrayBuffer = (file: File): Promise<Uint8Array> => {
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
        reader.readAsArrayBuffer(file);
    });
};

// --- Lógica de CIFRADO ---

document.getElementById('btnEncrypt')?.addEventListener('click', async () => {
    const fileInput = document.getElementById('fileToEncrypt') as HTMLInputElement;

    if (!fileInput.files?.length) {
        return alert("Por favor selecciona un archivo ");
    }

    const file = fileInput.files[0];
    const data = await readFileAsArrayBuffer(file);

    try {


        const cipherObject = {
            data: data,
            file_type: file.type,
            ownerKey: owner.publicKey,
            recipients: [{username: "Owner", key: owner.publicKey},{username: 'Alice', key: user1Keys.publicKey}]
        };

        const { cipherText, metaData } = await cryptoSvc.encrypt_file(cipherObject);

        const jsonMetaData = JSON.stringify(metaData);
        downloadFile(cipherText, `${file.name}.enc`, 'application/octet-stream');
        downloadFile(jsonMetaData, `metadata.json`, 'application/json');
        alert("Cifrado completado exitosamente.");
    } catch (e) {
        console.error("Error en cifrado:", e);
        alert("Error al cifrar el archivo.");
    }
});

// --- Lógica de DESCIFRADO ---

document.getElementById('btnDecrypt')?.addEventListener('click', async () => {
    const cipherFileInput = document.getElementById('cipherFile') as HTMLInputElement;
    const metaFileInput = document.getElementById('metadataFile') as HTMLInputElement;

    if (!cipherFileInput.files?.[0] || !metaFileInput.files?.[0]) {
        return alert("Faltan datos obligatorios para el descifrado.");
    }

    try {
        const cipherText = await readFileAsArrayBuffer(cipherFileInput.files[0]);
        const metaText = await metaFileInput.files[0].text();
        const metaData = JSON.parse(metaText);


        const userCredential = metaData.recipients.find((r:any) => r.username === 'Alice');
        if (!userCredential){
            alert("El usuario no tiene permiso para descifrar")
            return;
        }


        const decryptedData = await cryptoSvc.decrypt_file(
            metaData,
            cipherText,
            user1Keys.privateKey,
            userCredential.key
        );

        // 3. Descargar el archivo recuperado
        const extension = metaData.file_type?.split('/')[1] || 'bin';
        downloadFile(decryptedData.buffer as ArrayBuffer, `recuperado.${extension}`, metaData.file_type);

        alert("¡Archivo descifrado con éxito!");
    } catch (e: any) {
        console.error("Error en descifrado:", e);
        alert(`Error: ${e.message || "Fallo en el descifrado. Verifica tu llave y el nombre de usuario."}`);
    }
});