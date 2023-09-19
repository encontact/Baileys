import { Boom } from '@hapi/boom'
import NodeCache from 'node-cache'
import readline from 'readline'
import makeWASocket, { 
	AnyMessageContent, 
	delay, 
	DisconnectReason, 
	fetchLatestBaileysVersion, 
	getAggregateVotesInPollMessage, 
	makeCacheableSignalKeyStore, 
	makeInMemoryStore, 
	PHONENUMBER_MCC, 
	proto, 
	useMultiFileAuthState, 
	WAMessageContent, 
	WAMessageKey,
	WAMessage,
	downloadContentFromMessage,
	WAConnectionState 
} from '../src'
import QRCode from 'qrcode'
import MAIN_LOGGER from '../src/Utils/logger'
import generateMessageUid from '../src/Utils/generateMessageUid'
import { MessageDispatcher } from '../src/Models/MessageDispatcher'
import { WhatsappStatus } from '../src/Models/WhatsappStatus'

import { FileSystemTokensManager } from '../src/Services/FileSystemTokensManager'
import  AxiosMessageDispatcher  from '../src/Services/AxiosMessageDispatcher'
import open from 'open'
import fs from 'fs'
import express from 'express'

const MsgType = [
	'conversation',
	'extendedTextMessage',
	'imageMessage',
	'stickerMessage',
	'videoMessage',
	'audioMessage',
	'documentMessage',
	'documentWithCaptionMessage',
	'contactMessage',
	'contactsArrayMessage',
	'protocolMessage',
	'reactionMessage',
  ] as const
  type MsgType = (typeof MsgType)[number]


const logger = MAIN_LOGGER.child({})
logger.level = 'debug'

let lastConnectionState :WAConnectionState 
let qrCode: string | null = null

const tokensManager = new FileSystemTokensManager()
const messageDispatcher = new AxiosMessageDispatcher(
  tokensManager,
  logger.child({}, { msgPrefix: '[AxiosMessageDispatcher] ', level: 'error' }),
)

tokensManager.getToken().then(token => {
	if (token?.sessionName) {
	  messageDispatcher.changeSessionName(token.sessionName)
	}
	if (token?.hook) {
	  messageDispatcher.changeHook(token.hook)
	}
	if (token?.lastSuccessfullHookCallTimestamp) {
	  messageDispatcher.changeLastSuccessfullHookCall(
		token.lastSuccessfullHookCallTimestamp,
	  )
	}
})


let socket: any  

const app = express()
app.use(express.json()) 
const port = 3333

// end points ******
app.get('/', (req, res) => {
    res.send('get method Hello World!')
})

app.get('/close', (req, res) => {
	res.send('get method close')
})


app.get('/logout', (req, res) => {
	res.send('get method logout')
})

app.get('/status', (req, res) => {
	logger.debug('getStatus method called')
	let result :any 

    if (lastConnectionState === 'open')  
		result = WhatsappStatus.CONNECTED
    if (lastConnectionState === 'connecting' && qrCode)
        result = WhatsappStatus.QRCODE
	if (lastConnectionState === 'connecting')
		result =  WhatsappStatus.CONNECTING

	res.status(200).json({ success: true, data: { status: result } })
})

app.get('/qrCode', (req, res) => {
	logger.debug('getQrCode method called')

	if (qrCode === null) {
		logger.debug('QRCode not available')
		//throw new Error('QRCode not available')
	  }

	  qrCode = QRCode.toDataURL(qrCode)

	  res.status(200).json({ success: true, data: { qrCode } })
})

app.get('/getChat', async (req, res) => {

	let sessionName = req.query.sessionName
	let id: string = req.query.chatId as string
	const metadata = await socket.groupMetadata(id).catch(() => null)
	if (!metadata) return res.status(500).json({ success: false, message: 'NOTFOUND' })

	const isAdmin = metadata.participants.some(
		contact =>
		  contact.admin &&
		  contact.id === socket?.user?.id.split(':')[0] + '@s.whatsapp.net',
	  )

	  const group =  {
		id: metadata.id,
		subject: metadata.subject,
		description: metadata.subject,
		isAdmin,
		isAnnounce: metadata.announce || false,
	  }

	  const result = {
		id: group.id,
		name: group.subject,
		isReadOnly: group.isAnnounce && !group.isAdmin,
		IsAnnounceGrpRestrict: group.isAnnounce && !group.isAdmin,
		Contact: {},
	  }

	res.status(200).json({ success: true, result })
})

app.post('/sendText', async (req, res) => {
	let body = req.body
	const { number, sessionName, text  } = body
	//await wASocket.sendMessageWTyping(text, sessionName)
	let msg: AnyMessageContent = { text: text }
	// Emulates typing states
	await socket.presenceSubscribe(number)
	await delay(500)

	await socket.sendPresenceUpdate('composing', number)
	await delay(2000)

	await socket.sendPresenceUpdate('paused', number)
	//
	const sendedMessage = await socket.sendMessage(number, msg)

	let remoteJid = sendedMessage.key.remoteJid
    if (remoteJid?.includes(':')) {
      remoteJid = remoteJid.split(':')[0] + '@g.us'
    }

	const { messageRef: newMessageRef } =
	{
		messageRef: generateMessageUid({
		  fromMe: sendedMessage.key.fromMe,
		  jid: remoteJid,
		  messageId: sendedMessage.key.id,
		})
	}

	res.json({ success: true, data: { id: newMessageRef } })
})




const useStore = !process.argv.includes('--no-store')
const doReplies = !process.argv.includes('--no-reply')
const usePairingCode = process.argv.includes('--use-pairing-code')
const useMobile = process.argv.includes('--mobile')

// external map to store retry counts of messages when decryption/encryption fails
// keep this out of the socket itself, so as to prevent a message decryption/encryption loop across socket restarts
const msgRetryCounterCache = new NodeCache()

// Read line interface
const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
const question = (text: string) => new Promise<string>((resolve) => rl.question(text, resolve))

// the store maintains the data of the WA connection in memory
// can be written out to a file & read from it
const store = useStore ? makeInMemoryStore({ logger }) : undefined
store?.readFromFile('./baileys_store_multi.json')
// save every 10s
setInterval(() => {
	store?.writeToFile('./baileys_store_multi.json')
}, 10_000)

// start a connection
const startSock = async() => {
	logger.trace('startSock method called')
	const { state, saveCreds } = await useMultiFileAuthState('baileys_auth_info')
	// fetch latest version of WA Web
	const { version, isLatest } = await fetchLatestBaileysVersion()
	//console.log(`using WA v${version.join('.')}, isLatest: ${isLatest}`)
	//logger.trace(`using WA v${version.join('.')}, isLatest: ${isLatest}`)

	const sock = makeWASocket({
		version,
		logger,
		printQRInTerminal: !usePairingCode,
		mobile: useMobile,
		keepAliveIntervalMs: 30_000,
		auth: {
			creds: state.creds,
			/** caching makes the store faster to send/recv messages */
			keys: makeCacheableSignalKeyStore(state.keys, logger),
		},
		msgRetryCounterCache,
		generateHighQualityLinkPreview: true,
		// ignore all broadcast messages -- to receive the same
		// comment the line below out
		// shouldIgnoreJid: jid => isJidBroadcast(jid),
		// implement to handle retries & poll updates
		getMessage,
	})

	store?.bind(sock.ev)

	// Pairing code for Web clients
	if(usePairingCode && !sock.authState.creds.registered) {
		if(useMobile) {
			throw new Error('Cannot use pairing code with mobile api')
		}

		const phoneNumber = await question('Please enter your mobile phone number:\n')
		const code = await sock.requestPairingCode(phoneNumber)
		console.log(`Pairing code: ${code}`)
	}

	// If mobile was chosen, ask for the code
	if(useMobile && !sock.authState.creds.registered) {
		const { registration } = sock.authState.creds || { registration: {} }

		if(!registration.phoneNumber) {
			registration.phoneNumber = await question('Please enter your mobile phone number:\n')
		}

		const libPhonenumber = await import("libphonenumber-js")
		const phoneNumber = libPhonenumber.parsePhoneNumber(registration!.phoneNumber)
		if(!phoneNumber?.isValid()) {
			throw new Error('Invalid phone number: ' + registration!.phoneNumber)
		}

		registration.phoneNumber = phoneNumber.format('E.164')
		registration.phoneNumberCountryCode = phoneNumber.countryCallingCode
		registration.phoneNumberNationalNumber = phoneNumber.nationalNumber
		const mcc = PHONENUMBER_MCC[phoneNumber.countryCallingCode]
		if(!mcc) {
			throw new Error('Could not find MCC for phone number: ' + registration!.phoneNumber + '\nPlease specify the MCC manually.')
		}

		registration.phoneNumberMobileCountryCode = mcc

		async function enterCode() {
			try {
				const code = await question('Please enter the one time code:\n')
				const response = await sock.register(code.replace(/["']/g, '').trim().toLowerCase())
				console.log('Successfully registered your phone number.')
				console.log(response)
				rl.close()
			} catch(error) {
				console.error('Failed to register your phone number. Please try again.\n', error)
				await askForOTP()
			}
		}

		async function enterCaptcha() {
			const response = await sock.requestRegistrationCode({ ...registration, method: 'captcha' })
			const path = __dirname + '/captcha.png'
			fs.writeFileSync(path, Buffer.from(response.image_blob!, 'base64'))

			open(path)
			const code = await question('Please enter the captcha code:\n')
			fs.unlinkSync(path)
			registration.captcha = code.replace(/["']/g, '').trim().toLowerCase()
		}

		async function askForOTP() {
			if (!registration.method) {
				let code = await question('How would you like to receive the one time code for registration? "sms" or "voice"\n')
				code = code.replace(/["']/g, '').trim().toLowerCase()
				if(code !== 'sms' && code !== 'voice') {
					return await askForOTP()
				}

				registration.method = code
			}

			try {
				await sock.requestRegistrationCode(registration)
				await enterCode()
			} catch(error) {
				console.error('Failed to request registration code. Please try again.\n', error)

				if(error?.reason === 'code_checkpoint') {
					await enterCaptcha()
				}

				await askForOTP()
			}
		}

		askForOTP()
	}

	const sendMessageWTyping = async(msg: AnyMessageContent, jid: string) => {
		await sock.presenceSubscribe(jid)
		await delay(500)

		await sock.sendPresenceUpdate('composing', jid)
		await delay(2000)

		await sock.sendPresenceUpdate('paused', jid)

		await sock.sendMessage(jid, msg)
	}

	// the process function lets you process all events that just occurred
	// efficiently in a batch
	sock.ev.process(
		// events is a map for event name => event data
		async(events) => {
			// something about the connection changed
			// maybe it closed, or we received all offline message or connection opened
			if(events['connection.update']) {
				const update = events['connection.update']
				const { connection, lastDisconnect, qr, isNewLogin } = update

				if (connection === 'close' || connection === 'open' || connection === 'connecting')
					lastConnectionState = connection as WAConnectionState
				logger.info(`lastConnectionState: ${lastConnectionState}`);

				let reason = new Boom(lastDisconnect?.error)?.output?.statusCode

				if(connection === 'close') {

					if (reason === DisconnectReason.badSession) {
						logger.error(`Bad Session, Please Delete /auth and Scan Again`)
						process.exit()
					} else if (reason === DisconnectReason.connectionClosed) {
						logger.warn("Connection closed, reconnecting....");
						await startSock()
					} else if (reason === DisconnectReason.connectionLost) {
						logger.warn("Connection Lost from Server, reconnecting...");
						await startSock()
					} else if (reason === DisconnectReason.connectionReplaced) {
						logger.error("Connection Replaced, Another New Session Opened, Please Close Current Session First");
						process.exit()
					} else if (reason === DisconnectReason.loggedOut) {
						logger.error(`Device Logged Out, Please Delete /auth and Scan Again.`)
						process.exit()
					} else if (reason === DisconnectReason.restartRequired) {
						logger.info("Restart Required, Restarting...");
						await startSock()
					} else if (reason === DisconnectReason.timedOut) {
						logger.warn("Connection TimedOut, Reconnecting...");
						await startSock()
					} else {
						logger.warn(`Unknown DisconnectReason: ${reason}: ${connection}`);
						await startSock()
					} 
				}


				if (isNewLogin) qrCode = null
      			if (qr) qrCode = qr
				//console.log('connection update', update)
				logger.debug({update}, 'connection update')

			}

			// credentials updated -- save them
			if(events['creds.update']) {
				await saveCreds()
			}

			if(events['labels.association']) {
				console.log(events['labels.association'])
				//logger.trace(events['labels.association'])

			}


			if(events['labels.edit']) {
				console.log(events['labels.edit'])
				//logger.trace(events['labels.edit'])
			}

			if(events.call) {
				console.log('recv call event', events.call)
				//logger.trace('recv call event', events.call)
			}

			const syncMessagesAfterTimestamp = messageDispatcher.getLastSuccessfullHookCall()
			
			// history received
			if (syncMessagesAfterTimestamp) {
			  if(events['messaging-history.set']) {
				const { chats, contacts, messages, isLatest } = events['messaging-history.set']
				logger.info(`recv messaging-history.set:: ${chats.length} chats, ${contacts.length} contacts, ${messages.length} msgs (is latest: ${isLatest})`, 'messaging-history.set')

				const processedMessages = await Promise.all(
					messages
					  .filter(message => {
						if (!message.messageTimestamp) return false
						const needToSync =
						  typeof message.messageTimestamp === 'number'
							? message.messageTimestamp > syncMessagesAfterTimestamp
							: message.messageTimestamp.toNumber() >
							  syncMessagesAfterTimestamp
						if (!needToSync) return false
						return true
					  })
					  .map(async message => {
						return await processMessage(message)
					  }),
				  )

				  processedMessages.sort((a, b) => {
					return a.messageTimestamp.toNumber() - b.messageTimestamp.toNumber()
				  })

				  processedMessages.forEach(message => {
					messageDispatcher.dispatch(message)
				  })

			  }
		    }

			// received a new message
			if(events['messages.upsert']) {
				const upsert = events['messages.upsert']
				logger.debug('recv messages ::' + JSON.stringify(upsert, undefined, 2), 'recv messages ')

				upsert.messages.forEach(async message => {
					logger.debug('recv Each messages: ', message)
					const processedMessage = await processMessage(message)
					if (processedMessage) {
						console.log('messageDispatcher.dispatch: ', processedMessage)
						logger.debug('messageDispatcher.dispatch: ', processedMessage)
						messageDispatcher.dispatch(processedMessage)
					}
				  })


				// if(upsert.type === 'notify') {
				// 	for(const msg of upsert.messages) {
				// 		if(!msg.key.fromMe && doReplies) {
				// 			console.log('replying to', msg.key.remoteJid)
				// 			logger.debug('replying to', msg.key.remoteJid)
				// 			await sock!.readMessages([msg.key])
				// 			//await sendMessageWTyping({ text: 'Hello there!' }, msg.key.remoteJid!)
				// 		}
				// 	}
				// }
			}

			// messages updated like status delivered, message deleted etc.
			if(events['messages.update']) {
				logger.info(JSON.stringify(events['messages.update'], undefined, 2), 'messages.update')

				const messages = events['messages.update']

				messages.forEach(async message => {
					if (message.key.fromMe && message.update?.status) {
					  let remoteJid = message.key.remoteJid
					  if (remoteJid?.includes(':')) {
						remoteJid = remoteJid.split(':')[0] + '@s.whatsapp.net'
					  }
			
					  const processedMessage = {
						id: generateMessageUid({
						  fromMe: message.key.fromMe,
						  jid: remoteJid,
						  messageId: message.key.id,
						}),
						type: 'chat',
						self: 'out',
						ack: getAck(message.update?.status),
						from: remoteJid,
						to: socket?.user?.id.split(':')[0] + '@s.whatsapp.net',
						...message,
					  }
			
					  messageDispatcher.dispatch(processedMessage)
					}
				  })



				for(const { key, update } of events['messages.update']) {
					if(update.pollUpdates) {
						const pollCreation = await getMessage(key)
						if(pollCreation) {
							console.log(
								'got poll update, aggregation: ',
								getAggregateVotesInPollMessage({
									message: pollCreation,
									pollUpdates: update.pollUpdates,
								})
							)
						}
					}
				}
			}

			if(events['message-receipt.update']) {
				//console.log(events['message-receipt.update'])
				const receipts = events['message-receipt.update']
				logger.info(events['message-receipt.update'], 'message-receipt.update')
				logger.info({ receipts }, 'message-receipt.update::')

				receipts.forEach(async receipt => {
					let remoteJid = receipt.key.remoteJid
					if (remoteJid?.includes(':')) {
					  remoteJid = remoteJid.split(':')[0] + '@g.us'
					}
					const processedMessage = {
						id: generateMessageUid({
						  fromMe: receipt.key.fromMe,
						  jid: remoteJid,
						  messageId: receipt.key.id,
						}),
						type: 'chat',
						self: 'out',
						ack: '2',
						from: remoteJid,
						to: socket?.user?.id.split(':')[0] + '@s.whatsapp.net',
						...receipt,
					  }
			  
					  messageDispatcher.dispatch(processedMessage)
					})
			}



			if(events['messages.reaction']) {
				//console.log(events['messages.reaction'])
				logger.info(events['messages.reaction'], 'messages.reaction')
			}

			if(events['presence.update']) {
				//console.log(events['presence.update'])
				logger.info(events['presence.update'], 'presence.update')
			}

			if(events['chats.update']) {
				//console.log(events['chats.update'])
				logger.info(events['chats.update'], 'chats.update')
			}

			if(events['contacts.update']) {
				for(const contact of events['contacts.update']) {
					if(typeof contact.imgUrl !== 'undefined') {
						const newUrl = contact.imgUrl === null
							? null
							: await sock!.profilePictureUrl(contact.id!).catch(() => null)
							//logger.trace(`contact ${contact.id} has a new profile pic: ${newUrl}`)
						console.log(
							`contact ${contact.id} has a new profile pic: ${newUrl}`,
						)
					}
				}
			}

			if(events['chats.delete']) {
				//console.log('chats deleted ', events['chats.delete'])
				logger.info(events['chats.delete'], 'chats deleted ')
			}
		}
	)

	return sock

	async function getMessage(key: WAMessageKey): Promise<WAMessageContent | undefined> {
		if(store) {
			const msg = await store.loadMessage(key.remoteJid!, key.id!)
			return msg?.message || undefined
		}

		// only if store is present
		return proto.Message.fromObject({})
	}
}


const getAck = (ack: proto.WebMessageInfo.Status | null) => {
    logger.debug({ ack }, 'getAck method called')
    if (ack == proto.WebMessageInfo.Status.PLAYED) return '4'
    if (ack == proto.WebMessageInfo.Status.SERVER_ACK) return '1'
    if (ack == proto.WebMessageInfo.Status.DELIVERY_ACK) return '2'
    if (ack == proto.WebMessageInfo.Status.READ) return '3'
  }


const downloadMessage = async (msg: any, msgType: any) => {
    logger.debug({ msgType }, 'downloadMessage method called')
    let buffer = Buffer.from([])
    try {
      const stream = await downloadContentFromMessage(msg, msgType)
      for await (const chunk of stream) {
        buffer = Buffer.concat([buffer, chunk])
      }
    } catch {
      return logger.error('Error downloading file-message')
    }
    return buffer.toString('base64')
  }

const findMsgType = (message: WAMessageContent): MsgType | null => {
    logger.debug('findMsgType method called')
    for (const type of MsgType) {
      if (message[type]) {
        return type
      }
    }
    return null
  }

let processMessage = async (msg: WAMessage): Promise<any> => {
    logger.debug('processMessage method called')
    const messageType =
      (msg.message && findMsgType(msg.message)) || 'unsupported'
	  logger.debug(`messageType: ${messageType}`)

    const isSenderKeyDistributionMessage =
      msg.message && !!msg.message['senderKeyDistributionMessage']
	  logger.debug(`isSenderKeyDistributionMessage: ${isSenderKeyDistributionMessage}`)

    const groupId = msg.message?.senderKeyDistributionMessage?.groupId
    const firstGroupMessage =
      groupId == msg.key?.remoteJid &&
      groupId?.includes('@g.us') &&
      msg.key?.remoteJid?.includes('@g.us')

    if (
      ['senderKeyDistributionMessage'].includes(messageType) &&
      !firstGroupMessage
    ) {
      return
    }

    //if (!msg.key.fromMe && !msg.key.remoteJid?.includes('broadcast')) {
	if (!msg.key.remoteJid?.includes('broadcast')) {
      const msgId = generateMessageUid({
        fromMe: msg.key.fromMe,
        jid: msg.key.remoteJid,
        messageId: msg.key.id,
      })
      const IsGroupMessage = msgId.includes('@g.us')
	  logger.debug(`IsGroupMessage: ${IsGroupMessage}`)

      // Verificar se o messageType = "senderKeyDistributionMessage"
      // Se for, deve ser feita as alterações no final do switch
      // Além disso, o messageType muda pra ser o parametro da posição [2]

      let wppMessage = {
        ...msg,
        id: msgId,
        type: 'unsupported',
        isGroupMsg: IsGroupMessage,
        chatId: msg.key?.remoteJid,
        self: 'in',
        ack: '0',
        from: msg.key.remoteJid,
        to: socket?.user?.id.split(':')[0] + '@s.whatsapp.net',
        fromMe: false,
        sender: {
          id: IsGroupMessage
            ? msg.key.participant || msg.participant
            : msg.key.remoteJid,
          name: msg.pushName,
        },
      } as any
      let contentBase64

      switch (messageType) {
        case 'conversation': {
          wppMessage = {
            ...wppMessage,
            type: 'chat',
            content: msg.message?.conversation,
            body: msg.message?.conversation,
          }
          break
        }

        case 'extendedTextMessage': {
          wppMessage = {
            ...wppMessage,
            type: 'chat',
            content: msg.message?.extendedTextMessage?.text,
            body: msg.message?.extendedTextMessage?.text,
          }
          break
        }
        case 'imageMessage':
          contentBase64 = await downloadMessage(
            msg.message?.imageMessage,
            'image',
          )

          wppMessage = {
            ...wppMessage,
            type: 'image',
            caption: msg.message?.imageMessage?.caption,
            mimetype: msg.message?.imageMessage?.mimetype,
            contentBase64,
          }
          break

        case 'stickerMessage':
          contentBase64 = await downloadMessage(
            msg.message?.stickerMessage,
            'sticker',
          )

          wppMessage = {
            ...wppMessage,
            type: 'sticker',
            mimetype: msg.message?.stickerMessage?.mimetype,
            contentBase64,
          }
          break

        case 'videoMessage':
          contentBase64 = await downloadMessage(
            msg.message?.videoMessage,
            'video',
          )

          wppMessage = {
            ...wppMessage,
            type: 'video',
            caption: msg.message?.videoMessage?.caption,
            mimetype: msg.message?.videoMessage?.mimetype,
            contentBase64,
          }
          break

        case 'audioMessage':
          contentBase64 = await downloadMessage(
            msg.message?.audioMessage,
            'audio',
          )

          wppMessage = {
            ...wppMessage,
            type: 'audio',
            mimetype: msg.message?.audioMessage?.mimetype,
            contentBase64,
          }
          break

        case 'documentMessage':
          contentBase64 = await downloadMessage(
            msg.message?.documentMessage,
            'document',
          )

          wppMessage = {
            ...wppMessage,
            type: 'image',
            caption: msg.message?.documentMessage?.caption,
            mimetype: msg.message?.documentMessage?.mimetype,
            fileName: msg.message?.documentMessage?.fileName,
            contentBase64,
          }
          break

        case 'documentWithCaptionMessage':
          contentBase64 = await downloadMessage(
            msg.message?.documentWithCaptionMessage?.message?.documentMessage,
            'document',
          )

          wppMessage = {
            ...wppMessage,
            type: 'image',
            caption:
              msg.message?.documentWithCaptionMessage?.message?.documentMessage
                ?.caption,
            mimetype:
              msg.message?.documentWithCaptionMessage?.message?.documentMessage
                ?.mimetype,
            fileName:
              msg.message?.documentWithCaptionMessage?.message?.documentMessage
                ?.fileName,
            contentBase64,
          }
          break

        case 'contactMessage':
          wppMessage = {
            ...wppMessage,
            type: 'vcard',
            body: msg.message?.contactMessage?.vcard,
          }
          break

        case 'contactsArrayMessage':
          wppMessage = {
            ...wppMessage,
            type: 'vcard',
            vcardList: msg.message?.contactsArrayMessage?.contacts,
          }
          break

        case 'protocolMessage':
          if (
            msg.message?.protocolMessage?.type ===
            proto.Message.ProtocolMessage.Type.REVOKE
          ) {
            wppMessage = {
              from: wppMessage.from,
              to: wppMessage.to,
              id: wppMessage.id,
              refId: `${msg.key.fromMe}_${msg.key.remoteJid}_${msg.message?.protocolMessage?.key?.id}`,
            }
            return wppMessage
          } else {
            // Aqui, se a mensagem de protocolo não for do tipo revoke, ignora a mensagem
            return null
          }

        case 'reactionMessage': {
          // TODO: Reações a mensagens ainda não são suportadas
          logger.info(
            'Nova mensagem do tipo reação a mensagem (emoji), mas ainda não é suportado. Mensagem ignorada.',
          )
          return null
        }
        default:
          break
      }
      if (isSenderKeyDistributionMessage) {
        const groupConversationId = `${msg.key.fromMe}_${msg.key.remoteJid}_${
          msg.key.id
        }_${msg.participant || msg.key.participant}`

        wppMessage = {
          ...wppMessage,
          id: groupConversationId,
          chatId: groupId,
          sender: {
            ...wppMessage.sender,
            id: msg.participant || msg.key.participant,
          },
        }
      }
      if (
        msg.message &&
        messageType !== 'unsupported' &&
        msg.message[messageType] &&
        Object.prototype.hasOwnProperty.call(
          msg.message[messageType as keyof proto.IMessage],
          'contextInfo',
        )
      ) {
        const messageTypeObject = msg.message[
          messageType as keyof proto.IMessage
        ] as any
        const quotedMsgId = `${msg.key.fromMe}_${messageTypeObject?.contextInfo.participant}_${messageTypeObject.contextInfo.stanzaId}`
        wppMessage = {
          ...wppMessage,
          quotedMsgId,
        }
      }

      return wppMessage
    }
  }


app.listen(port, () => {
	 startSock()
	.then(x => {
		socket = x
	 	//console.log(x)
	 })
	console.log(`Example app listening at http://localhost:${port}`)
})
