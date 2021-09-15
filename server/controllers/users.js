import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

import User from "../models/user.js";

export const signin = async (request, response) => {
  const { email, password } = request.body;

  try {
    const existingUser = await User.findOne({ email });
    if (!existingUser) {
      return response.status(400).json({ message: "User does not exist" });
    }

    const isPasswordCorrect = await bcrypt.compare(
      password,
      existingUser.password
    );
    if (!isPasswordCorrect)
      return response.status(400).json({ message: "Invalid Password." });

    const token = jwt.sign(
      { email: email.existingUser.email, id: existingUser._id },
      "text",
      { expiresIn: "1h" }
    );

    response.status(200).json({ result: existingUser, token });
  } catch (error) {
    response.status(500).json({ message: "Something went wrong" });
  }
};

export const signup = async (request, response) => {
  const { email, password, firstName, lastName, confirmPassword } =
    request.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser)
      return response.status(400).json({ message: "User already exists" });

    if (password !== confirmPassword)
      return response.status(400).json({ message: "Passwords do not match." });

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await User.create({
      email,
      password: hashedPassword,
      name: `${firstName}${lastName}`,
    });

    const token = jwt.sign({ email: result.email, id: result._id }, "text", {
      expiresIn: "1h",
    });

    response.status(200).json({ result: result, token });
  } catch (error) {
    response.status(500).json({ message: "Something went wrong" });
  }
};
