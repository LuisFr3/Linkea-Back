import type { Request, Response } from 'express'
import { validationResult } from 'express-validator'
import slug from 'slug'
import formidable from 'formidable'
import { v4 as uuid } from 'uuid'
import User from "../models/User"
import { checkPassword, hashPassword } from '../utils/auth'
import { generateJWT } from '../utils/jwt'
import cloudinary from '../config/cloudinary'
import transporter  from "../config/mailer"
import { generateResetToken, generateTokenExpiration } from "../utils/tokens"


export const createAccount = async (req: Request, res: Response) => {
    const { email, password } = req.body
    const userExists = await User.findOne({ email })
    if (userExists) {
        const error = new Error('Un usuario con ese mail ya esta registrado')
        return res.status(409).json({ error: error.message })
    }

    const handle = slug(req.body.handle, '')
    const handleExists = await User.findOne({ handle })
    if (handleExists) {
        const error = new Error('Nombre de usuario no disponible')
        return res.status(409).json({ error: error.message })
    }

    const user = new User(req.body)
    user.password = await hashPassword(password)
    user.handle = handle

    await user.save()
    res.status(201).send('Registro Creado Correctamente')
}

export const login = async (req: Request, res: Response) => {
    // Manejar errores
    let errors = validationResult(req)
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() })
    }

    const { email, password } = req.body

    // Revisar si el usuario esta registrado
    const user = await User.findOne({ email })
    if (!user) {
        const error = new Error('El Usuario no existe')
        return res.status(404).json({ error: error.message })
    }

    // Comprobar el password
    const isPasswordCorrect = await checkPassword(password, user.password)
    if (!isPasswordCorrect) {
        const error = new Error('Password Incorrecto')
        return res.status(401).json({ error: error.message })
    }

    const token = generateJWT({ id: user._id })

    res.send(token)
}

export const getUser = async (req: Request, res: Response) => {
    res.json(req.user)
}

export const updateProfile = async (req: Request, res: Response) => {
    try {
        const { description, links } = req.body

        const handle = slug(req.body.handle, '')
        const handleExists = await User.findOne({ handle })
        if (handleExists && handleExists.email !== req.user.email) {
            const error = new Error('Nombre de usuario no disponible')
            return res.status(409).json({ error: error.message })
        }

        // Actualizar el usuario
        req.user.description = description
        req.user.handle = handle
        req.user.links = links
        await req.user.save()
        res.send('Perfil Actualizado Correctamente')

    } catch (e) {
        const error = new Error('Hubo un error')
        return res.status(500).json({ error: error.message })
    }
}

export const uploadImage = async (req: Request, res: Response) => {
    const form = formidable({ multiples: false })
    try {
        form.parse(req, (error, fields, files) => {
            cloudinary.uploader.upload(files.file[0].filepath, { public_id: uuid() }, async function (error, result) { //esta es la linea 95
                if (error) {
                    const error = new Error('Hubo un error al subir la imagen')
                    return res.status(500).json({ error: error.message })
                }
                if (result) {
                    req.user.image = result.secure_url
                    await req.user.save()
                    res.json({ image: result.secure_url })
                }
            })
        })
    } catch (e) {
        const error = new Error('Hubo un error')
        return res.status(500).json({ error: error.message })
    }
}

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body

    // Buscar usuario por email
    const user = await User.findOne({ email })
    if (!user) {
      const error = new Error("No existe un usuario con ese email")
      return res.status(404).json({ error: error.message })
    }

    // Generar token de reset
    const resetToken = generateResetToken()
    const tokenExpiration = generateTokenExpiration()

    // Guardar token en la base de datos
    user.resetPasswordToken = resetToken
    user.resetPasswordExpires = tokenExpiration
    await user.save()

    // Crear el link de reset
    const resetUrl = `${process.env.FRONTEND_URL}/auth/reset-password/${resetToken}`

    // Configurar el email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Recuperación de Contraseña - Linkea",
      html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #059669;">Recuperación de Contraseña</h2>
                    <p>Hola <strong>${user.name}</strong>,</p>
                    <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta en Linkea.</p>
                    <p>Haz clic en el siguiente enlace para crear una nueva contraseña:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetUrl}" 
                           style="background-color: #059669; color: white; padding: 12px 24px; 
                                  text-decoration: none; border-radius: 6px; display: inline-block;">
                            Restablecer Contraseña
                        </a>
                    </div>
                    <p><strong>Este enlace expirará en 1 hora.</strong></p>
                    <p>Si no solicitaste este cambio, puedes ignorar este email.</p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #e5e7eb;">
                    <p style="color: #6b7280; font-size: 14px;">
                        Si tienes problemas con el botón, copia y pega este enlace en tu navegador:<br>
                        <a href="${resetUrl}" style="color: #059669;">${resetUrl}</a>
                    </p>
                </div>
            `,
    }

    // Enviar email
    await transporter.sendMail(mailOptions)

    res.json({ message: "Se ha enviado un email con las instrucciones para restablecer tu contraseña" })
  } catch (error) {
    console.error("Error en forgotPassword:", error)
    const errorMessage = new Error("Hubo un error al procesar la solicitud")
    return res.status(500).json({ error: errorMessage.message })
  }
}

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token } = req.params
    const { password } = req.body

    // Buscar usuario por token
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() }, // Token no expirado
    })

    if (!user) {
      const error = new Error("Token inválido o expirado")
      return res.status(400).json({ error: error.message })
    }

    // Actualizar contraseña
    user.password = await hashPassword(password)
    user.resetPasswordToken = ""
    user.resetPasswordExpires = null
    await user.save()

    res.json({ message: "Contraseña actualizada correctamente" })
  } catch (error) {
    console.error("Error en resetPassword:", error)
    const errorMessage = new Error("Hubo un error al restablecer la contraseña")
    return res.status(500).json({ error: errorMessage.message })
  }
}


export const getUserByHandle = async (req: Request, res: Response) => {
    try {
        const { handle } = req.params
        const user = await User.findOne({ handle }).select('-_id -__v -email -password')
        if (!user) {
            const error = new Error('El Usuario no existe')
            return res.status(404).json({ error: error.message })
        }
        res.json(user)
    } catch (e) {
        const error = new Error('Hubo un error')
        return res.status(500).json({ error: error.message })
    }
}

export const searchByHandle = async (req: Request, res: Response) => {
    try {
        const { handle } = req.body
        const userExists = await User.findOne({handle})
        if(userExists) {
            const error = new Error(`${handle} ya está registrado`)
            return res.status(409).json({error: error.message})
        }
        res.send(`${handle} está disponible`)
    } catch (e) {
        const error = new Error('Hubo un error')
        return res.status(500).json({ error: error.message })
    }
}