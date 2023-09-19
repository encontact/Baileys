import axios from 'axios'
import { MessageDispatcher } from '../Models/MessageDispatcher'
import { Logger } from 'pino'
import { TokensManager } from '../Models/TokensManager'


export default class AxiosMessageDispatcher implements MessageDispatcher {
    private tokensManager: TokensManager
    private sessionName: string | null = null
    private hook: string | null = null
    private lastSuccessfullHookCall: number | null = null
    private readonly logger: Logger
  
    constructor(tokensManager: TokensManager, logger: Logger) {
      this.tokensManager = tokensManager
      this.logger = logger
    }
  
    changeSessionName(sessionName: string): void {
      this.logger.debug({ sessionName }, 'changeSessionName method called')
      this.sessionName = sessionName
    }
  
    changeHook(hook: string): void {
      this.logger.debug({ hook }, 'changeHook method called')
      this.hook = hook
    }
  
    changeLastSuccessfullHookCall(lastSuccessfullHookCall: number): void {
      this.logger.debug(
        { lastSuccessfullHookCall },
        'changeLastSuccessfullHookCall method called',
      )
      this.lastSuccessfullHookCall = lastSuccessfullHookCall
    }
  
    getLastSuccessfullHookCall(): number | null {
      this.logger.debug(
        { lastSuccessfullHookCall: this.lastSuccessfullHookCall },
        'getLastSuccessfullHookCall method called',
      )
      return this.lastSuccessfullHookCall
    }
  
    getSessionName(): string | null {
      this.logger.debug(
        { sessionName: this.sessionName },
        'getSessionName method called',
      )
      return this.sessionName
    }
  
    async dispatch(data: any): Promise<void> {
      this.logger.debug(data, 'dispatch method called')
      if (!this.hook) {
        this.logger.error('Hook is not set')
        return
      }
      if (!this.sessionName) {
        this.logger.error('Session name is not set')
        return
      }
      try {
        await axios({
          method: 'post',
          url: this.hook,
          headers: {
            'Content-Type': 'application/json',
          },
          data,
        })
        const timestamp = Math.floor(Date.now() / 1000)
        this.changeLastSuccessfullHookCall(timestamp)
        await this.tokensManager.saveToken({
          sessionName: this.sessionName,
          hook: this.hook,
          lastSuccessfullHookCallTimestamp: timestamp,
        })
      } catch (error) {
        this.logger.error({ error }, 'Error call webhook onMessage: ')
      }
    }
  }