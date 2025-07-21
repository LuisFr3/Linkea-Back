import { CorsOptions } from 'cors'

const whiteList = [
  process.env.FRONTEND_URL,     
]

export const corsConfig: CorsOptions = {
  origin(origin, callback) {
    console.log('Origin recibido:', origin)
    console.log('Whitelist:', whiteList)

    if (!origin || whiteList.includes(origin)) {
      callback(null, true)
    } else {
      callback(new Error('Error de CORS'))
    }
  },
  credentials: true, 
}
