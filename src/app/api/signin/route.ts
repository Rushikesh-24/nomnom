import { turso } from "@/lib/tursoclient";
import { compare } from "bcryptjs";
import jwt from "jsonwebtoken";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const email = body.email;
    const password = body.password;

    if (!email || !password) {
      return Response.json(
        { message: "Email and password are required" },
        { status: 400 }
      );
    }

    const { rows: existingUser } = await turso.execute(
      "SELECT * FROM restaurants WHERE email = ?",
      [email]
    );
    if (existingUser.length === 0) {
      return Response.json(
        { message: "Invalid email or password" },
        { status: 401 }
      );
    }

    const user = existingUser[0];
    const isPasswordValid = await compare(password, user.password as string);

    if (!isPasswordValid) {
      return Response.json(
        { message: "Invalid email or password" },
        { status: 401 }
      );
    }

    const restaurantInfo = {
      id: typeof user.id === "bigint" ? user.id.toString() : user.id,
      email: user.email,
    };
    const token = jwt.sign(restaurantInfo, process.env.JWT_SECRET as string, {
      expiresIn: "1h",
    });

    const response = NextResponse.json({ message: "Signin successful", token });
    
    response.cookies.set("token", token, {
      httpOnly: true, // Prevents client-side JS from reading the cookie
      secure: process.env.NODE_ENV === "production", // HTTPS only in prod
      sameSite: "strict",
      path: "/", // Available on all routes
      maxAge: 3600, // 1 hour in seconds
    });

    return response;
    
  } catch (error) {
    console.error("Unexpected error in signin route:", error);
    if (error instanceof SyntaxError) {
      return Response.json(
        { message: "Invalid or missing JSON body" },
        { status: 400 }
      );
    }
    return Response.json({ message: "Internal server error" }, { status: 500 });
  }
}
