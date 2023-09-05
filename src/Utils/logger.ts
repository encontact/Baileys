import P from 'pino'

export default P(
    { timestamp: () => `,"time":"${new Date().toJSON()}"`, 
      transport:{
                    target: 'pino-pretty',
                    options: { destination: '/home/ubuntu/logs/log.txt' }
                    //options: { destination: 'C:/logs/log.txt' }
                }
            }
)