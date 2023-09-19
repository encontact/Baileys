export type Token = {
    sessionName: string
    hook?: string
    lastSuccessfullHookCallTimestamp?: number
  }


  export interface TokensManager {
    getTokensPath(): string
    saveToken(token: Token): Promise<void>
    getToken(): Promise<Token | null>
    removeToken(): Promise<void>
  }