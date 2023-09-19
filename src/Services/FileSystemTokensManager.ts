import fs from 'fs'
import { Token, TokensManager } from '../Models/TokensManager'


export class FileSystemTokensManager implements TokensManager {
    private readonly TOKENS_PATH = './tokens'
  
    getTokensPath(): string {
      return this.TOKENS_PATH
    }
  
    async saveToken(token: Token): Promise<void> {
      if (!fs.existsSync(this.TOKENS_PATH)) {
        fs.mkdirSync(this.TOKENS_PATH)
      }
      fs.writeFileSync(`${this.TOKENS_PATH}/token.json`, JSON.stringify(token))
    }
    async getToken(): Promise<Token | null> {
      const tokenFilePath = `${this.TOKENS_PATH}/token.json`
      if (!fs.existsSync(tokenFilePath)) {
        return null
      }
      const tokenFile = fs.readFileSync(tokenFilePath)
      const token = JSON.parse(tokenFile.toString())
      return {
        sessionName: token.sessionName,
        hook: token.hook,
        lastSuccessfullHookCallTimestamp: token.lastSuccessfullHookCallTimestamp
          ? Number(token.lastSuccessfullHookCallTimestamp)
          : undefined,
      }
    }
    async removeToken(): Promise<void> {
      if (!fs.existsSync(this.TOKENS_PATH)) {
        return
      }
      fs.rm(this.TOKENS_PATH, { recursive: true }, err => {
        if (err) {
          throw err
        }
      })
    }
  }