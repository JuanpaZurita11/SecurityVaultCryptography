import React, { useState, type ChangeEvent } from 'react';
import { KeyManager, bytesToB64 } from 'd5-crypto';

const AdministradorDeLlaves: React.FC = () => {
  // Tipando explícitamente los estados
  const keyManager = new KeyManager();
  const [llavesGeneradas, setLlavesGeneradas] = useState<boolean>(false);
  const [llavePublica, setLlavePublica] = useState<Uint8Array>(new Uint8Array(0));
  const [llavePrivada, setLlavePrivada] = useState<Uint8Array>(new Uint8Array(0));

  const [contenidoArchivo, setContenidoArchivo] = useState<string>('');
  const [nombreArchivoCargado, setNombreArchivoCargado] = useState<string>('');


  const manejarRefresco = (): void => {
    setLlavesGeneradas(false);
    setLlavePublica(new Uint8Array(0));
    setLlavePrivada(new Uint8Array(0));
  };

  const descargarArchivo = async (nombreArchivo: string, tipo: "public" | "private") : Promise<void> => {
    let contenido;
    if (tipo === "public") {
      contenido = await keyManager.serialize_public_key_pem(llavePublica);
    } else {
      contenido = await keyManager.serialize_private_key_pem(llavePrivada);
    }
    const blob = new Blob([contenido], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const enlace = document.createElement('a');
    enlace.href = url;
    enlace.download = nombreArchivo;
    enlace.click();
    URL.revokeObjectURL(url);
  };

  const manejarGeneracion = (): void => {
    const keypair = keyManager.generate_key_pair();
    setLlavePublica(keypair.publicKey);
    setLlavePrivada(keypair.privateKey);
    setLlavesGeneradas(true);
  };

  const manejarCargaArchivo = (evento: ChangeEvent<HTMLInputElement>): void => {
    // El operador '?.' previene errores si files es null
    const archivo = evento.target.files?.[0];
    if (!archivo) return;

    setNombreArchivoCargado(archivo.name);
    const lector = new FileReader();

    // Tipamos el evento de carga del lector
    lector.onload = async (e: ProgressEvent<FileReader>) => {
      // Como usamos readAsText, sabemos que el resultado será un string
      if (e.target?.result) {
        const contenido = e.target.result as string;
        let rawKey = null;

        if (contenido.includes('BEGIN PUBLIC KEY')) {
          rawKey = await keyManager.deserialize_public_key_pem(contenido);
        }
        else {
          rawKey = await keyManager.deserialize_private_key_pem(contenido);
        }
        setContenidoArchivo(bytesToB64(rawKey));
      }
    };
    lector.readAsText(archivo);
  };

  return (
    <div className="flex flex-col md:flex-row min-h-screen bg-gray-100 font-sans text-gray-800">

      {/* PANEL IZQUIERDO: Generar Llaves */}
      <div className="md:w-1/2 p-8 md:p-12 bg-white shadow-2xl z-10 flex flex-col">
        <div className="mb-8">
          <h2 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-indigo-600 mb-2">
            Generador de Llaves
          </h2>
          <p className="text-gray-500 text-sm">Crea tu par de llaves criptográficas de forma segura.</p>
        </div>

        {!llavesGeneradas ? (
          <div className="flex-grow flex items-center justify-center">
            <button
              onClick={manejarGeneracion}
              className="group relative px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 text-white font-bold rounded-2xl shadow-lg hover:shadow-xl transition-all duration-300 transform hover:-translate-y-1 overflow-hidden focus:outline-none focus:ring-4 focus:ring-blue-300"
            >
              <div className="absolute inset-0 w-full h-full bg-white opacity-0 group-hover:opacity-10 transition-opacity duration-300"></div>
              <span className="flex items-center gap-3">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
                Generar Nuevo Par
              </span>
            </button>
          </div>
        ) : (
          <div className="flex flex-col space-y-6">
            <div className="bg-gray-50 p-5 rounded-2xl border border-gray-200 shadow-sm transition-all hover:shadow-md">
              <div className="flex justify-between items-center mb-3">
                <label className="font-semibold text-gray-700 flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-green-500 shadow-sm"></span> Llave Pública
                </label>
                <button
                  onClick={() => descargarArchivo('llave_publica.pem', 'public')}
                  className="text-xs font-bold px-3 py-1.5 bg-white border border-gray-300 hover:bg-gray-100 text-gray-700 rounded-lg transition-colors flex items-center gap-1 shadow-sm"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                  Descargar
                </button>
              </div>
              <textarea
                className="w-full text-xs font-mono text-gray-500 bg-transparent border-0 focus:ring-0 resize-none outline-none"
                rows={4} value={bytesToB64(llavePublica)} readOnly
              />
            </div>

            <div className="bg-gray-50 p-5 rounded-2xl border border-gray-200 shadow-sm transition-all hover:shadow-md">
              <div className="flex justify-between items-center mb-3">
                <label className="font-semibold text-gray-700 flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full bg-red-500 shadow-sm"></span> Llave Privada
                </label>
                <button
                  onClick={() => descargarArchivo('llave_privada.pem', 'private')}
                  className="text-xs font-bold px-3 py-1.5 bg-red-50 border border-red-200 hover:bg-red-100 text-red-700 rounded-lg transition-colors flex items-center gap-1 shadow-sm"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path></svg>
                  Descargar
                </button>
              </div>
              <textarea
                className="w-full text-xs font-mono text-gray-500 bg-transparent border-0 focus:ring-0 resize-none outline-none"
                rows={4} value={bytesToB64(llavePrivada)} readOnly
              />
            </div>

            <button
              onClick={manejarRefresco}
              className="mt-2 flex items-center justify-center gap-2 text-gray-500 hover:text-indigo-600 font-medium transition-colors py-2"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
              Crear otro par
            </button>
          </div>
        )}
      </div>

      {/* PANEL DERECHO: Cargar Llave */}
      <div className="md:w-1/2 p-8 md:p-12 bg-slate-50 flex flex-col">
        <div className="mb-8">
          <h2 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-teal-600 to-emerald-600 mb-2">
            Lector de Llaves
          </h2>
          <p className="text-gray-500 text-sm">Carga una llave desde tu sistema para inspeccionarla.</p>
        </div>

        <div className="flex-grow flex flex-col">
          {!contenidoArchivo ? (
            <div className="flex-grow flex items-center justify-center">
              <label className="flex flex-col items-center justify-center w-full h-72 border-2 border-dashed border-teal-300 rounded-3xl bg-teal-50/50 hover:bg-teal-50 transition-colors cursor-pointer group shadow-sm">
                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                  <svg className="w-16 h-16 text-teal-400 mb-4 group-hover:scale-110 group-hover:text-teal-500 transition-all duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                  <p className="mb-2 text-lg text-teal-800 font-semibold">Selecciona un archivo</p>
                  <p className="text-sm text-teal-600">o arrástralo y suéltalo aquí</p>
                </div>
                <input type="file" className="hidden" accept=".pem" onChange={manejarCargaArchivo} />
              </label>
            </div>
          ) : (
            <div className="flex flex-col h-full">
              <div className="flex justify-between items-center mb-4">
                <span className="px-4 py-2 bg-teal-100 text-teal-800 rounded-xl text-sm font-bold flex items-center gap-2 shadow-sm border border-teal-200">
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                  {nombreArchivoCargado}
                </span>
                <button onClick={() => setContenidoArchivo('')} className="text-sm text-gray-500 hover:text-red-600 font-medium transition-colors">
                  Cerrar archivo
                </button>
              </div>

              <div className="flex-grow bg-gray-900 rounded-2xl shadow-xl relative overflow-hidden flex flex-col border border-gray-800">
                <div className="w-full h-10 bg-gray-800 flex items-center px-4 gap-2 border-b border-gray-700">
                  <div className="w-3 h-3 rounded-full bg-red-500"></div>
                  <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                  <div className="w-3 h-3 rounded-full bg-green-500"></div>
                  <span className="ml-2 text-xs text-gray-400 font-mono">visor_de_llaves</span>
                </div>
                <textarea
                  className="w-full h-full p-6 text-sm font-mono text-teal-300 bg-transparent border-0 focus:ring-0 resize-none outline-none leading-relaxed"
                  value={contenidoArchivo}
                  readOnly
                />
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  );
};

export default AdministradorDeLlaves;