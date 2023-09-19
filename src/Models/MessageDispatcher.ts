export interface MessageDispatcher {
    changeSessionName(sessionName: string): void
    changeHook(hook: string): void
    changeLastSuccessfullHookCall(lastSuccessfullHookCall: number): void
    getSessionName(): string | null
    getLastSuccessfullHookCall(): number | null
    dispatch(data: any): Promise<void>
  }