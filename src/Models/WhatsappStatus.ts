export const WhatsappStatus = {
    NOTFOUND: 'NOTFOUND', // Servidor express ON mas Whatsapp não iniciado
    DISCONNECTED: 'DISCONNECTED', // Whatsapp offline, esperando comando start
    CONNECTING: 'CONNECTING', // Tentando conexão com Whatsapp
    QRCODE: 'QRCODE', // QrCode disponível para leitura
    CONNECTED: 'CONNECTED', // Whatsapp conectado
  } as const