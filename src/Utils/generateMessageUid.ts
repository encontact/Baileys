export default function generateMessageUid({
    fromMe,
    jid,
    messageId,
  }: {
    jid?: string | null
    messageId?: string | null
    fromMe?: boolean | null
  }): string {
    const isGroup = jid?.includes('@g.us')
    return `${fromMe || false}_${
      isGroup ? jid : jid?.split('@')[0].concat('@c.us') // TODO: O sufixo não deveria ser hardcoded (EnkiWhatsappWebDispatcher.cs linha 273)
    }_${messageId}`
  }