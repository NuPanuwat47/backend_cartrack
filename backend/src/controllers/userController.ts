import { Request, Response } from "express";
import bcrypt from "bcrypt";
import User from "../models/User";
import jwt from "jsonwebtoken";

// CREATE USER
export const createUser = async (req: Request, res: Response): Promise<void> => {
    const { email, password, firstName, lastName, role } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(400).json({ message: "อีเมลนี้ มีผู้ใช้อยู่ในระบบแล้ว" });
            return;
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({
            email,
            password: hashedPassword,
            firstName,
            lastName,
            role,
            profile_img:
                "https://res.cloudinary.com/dboau6axv/image/upload/v1735641179/qa9dfyxn8spwm0nwtako.jpg",
        });

        await newUser.save();

        res.status(201).json({
            message: "User created successfully",
            user: {
                id: newUser._id,
                email: newUser.email,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                role: newUser.role,
                profile_img: newUser.profile_img,
            },
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to create user", error });
    }
};

// UPDATE USER
export const updateUser = async (req: Request, res: Response): Promise<void> => {
    const { userId, targetUserId, firstName, lastName, email, newRole , currentUserId: bodyCurrentUserId, currentUserRole: bodyCurrentUserRole } = req.body;
    let currentUserId = bodyCurrentUserId;
    let currentUserRole = bodyCurrentUserRole;
    const idToUpdate = targetUserId || userId;
    try {
        if (!idToUpdate) {
            res.status(400).json({ message: "Missing user id to update" });
            return;
        }

        // หาก frontend ไม่ส่ง currentUserId/currentUserRole ให้พยายาม decode จาก Authorization header
        if ((!currentUserId || !currentUserRole) && typeof req.headers.authorization === 'string') {
            const auth = req.headers.authorization;
            if (auth.startsWith('Bearer ')) {
                const token = auth.split(' ')[1];
                try {
                    const decoded: any = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
                    currentUserId = currentUserId || decoded.userId || decoded.id || decoded._id;
                    currentUserRole = currentUserRole || decoded.role || decoded.roleFromJWT || decoded.role_name;
                } catch (err) {
                    // ถ้า token ไม่ถูกต้อง จะไม่ล้มทันที — ปล่อยให้ตรวจสอบสิทธิ์ต่อไปและคืน 403 ถ้าจำเป็น
                    console.warn('Failed to verify token inside updateUser:', err);
                }
            }
        }

        const user = await User.findById(idToUpdate);
        if (!user) {
            res.status(404).json({ message: "User not found" });
            return;
        }

        // ถ้ากำลังอัพเดตข้อมูลของคนอื่น ให้ตรวจสอบสิทธิ์จาก caller (token หรือ body)
        if (currentUserId && String(currentUserId) !== String(idToUpdate)) {
            const roleLower = (currentUserRole || "").toString().toLowerCase();
            if (roleLower !== "admin" && roleLower !== "super admin") {
                res.status(403).json({ message: "Insufficient permissions to update other users" });
                return;
            }
        }

        // ถ้าพยายามเปลี่ยน role ให้แน่ใจว่าผู้เรียกมีสิทธิ์
        if (newRole) {
            const roleLower = (currentUserRole || "").toString().toLowerCase();
            if (roleLower !== "admin" && roleLower !== "super admin") {
                res.status(403).json({ message: "Insufficient permissions to change role" });
                return;
            }
            user.role = newRole;
        }

        // ตรวจสอบอีเมลซ้ำ (ยกเว้นเป็นของ user เดิม)
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser && String(existingUser._id) !== String(user._id)) {
                res.status(400).json({ message: "อีเมลนี้ มีผู้ใช้อยู่ในระบบแล้ว" });
                return;
            }
            user.email = email;
        }

        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;

        await user.save();

        res.status(200).json({
            message: "User updated successfully",
            user: {
                id: user._id,
                email: user.email,
                firstName: user.firstName,
                lastName: user.lastName,
                role: user.role,
                profile_img: user.profile_img,
            },
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to update user", error });
    }
    // try {
    //     const user = await User.findById(userId);
    //     if (!user) {
    //         res.status(404).json({ message: "User not found" });
    //         return;
    //     }

    //     // ตรวจสอบอีเมลซ้ำ
    //     if (email && email !== user.email) {
    //         const existingUser = await User.findOne({ email });
    //         if (existingUser) {
    //             res.status(400).json({ message: "อีเมลนี้ มีผู้ใช้อยู่ในระบบแล้ว" });
    //             return;
    //         }
    //     }

    //     user.firstName = firstName || user.firstName;
    //     user.lastName = lastName || user.lastName;
    //     user.email = email || user.email;
    //     if (newRole) user.role = newRole;

    //     await user.save();

    //     res.status(200).json({
    //         message: "User updated successfully",
    //         user: {
    //             id: user._id,
    //             email: user.email,
    //             firstName: user.firstName,
    //             lastName: user.lastName,
    //             role: user.role,
    //             profile_img: user.profile_img,
    //         },
    //     });
    // } catch (error) {
    //     res.status(500).json({ message: "Failed to update user", error });
    // }
};

// DELETE USER
export const deleteUser = async (req: Request, res: Response): Promise<void> => {
    const { userId, currentUserId } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ message: "User not found" });
            return;
        }

        if (userId === currentUserId) {
            res.status(400).json({ message: "Cannot delete your own account" });
            return;
        }

        await User.findByIdAndDelete(userId);

        res.status(200).json({ message: "User deleted successfully" });
    } catch (error) {
        res.status(500).json({ message: "Failed to delete user", error });
    }
};
