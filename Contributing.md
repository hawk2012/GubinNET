# **Contributing to GubinNET**

Thank you for your interest in contributing to **GubinNET**! We welcome contributions from developers of all skill levels. Whether you're fixing a bug, adding a feature, or improving documentation, your help is greatly appreciated.

## **Table of Contents**

1. [Getting Started](#getting-started)
2. [How to Contribute](#how-to-contribute)
   - [Reporting Issues](#reporting-issues)
   - [Submitting Pull Requests](#submitting-pull-requests)
3. [Development Setup](#development-setup)
4. [Coding Standards](#coding-standards)
5. [Testing](#testing)
6. [Documentation](#documentation)
7. [Code of Conduct](#code-of-conduct)

---

## **Getting Started**

Before contributing, please familiarize yourself with the following:

- **Repository**: [GubinNET on GitHub](https://github.com/hawk2012/GubinNET)
- **README**: Review the [README.md](README.md) for an overview of the project.
- **License**: GubinNET is licensed under the MIT License. By contributing, you agree to abide by the terms of this license.

## **How to Contribute**

### **Reporting Issues**

If you encounter a bug or have a feature request, please open an issue on GitHub. Follow these guidelines:

1. **Search First**: Check if the issue has already been reported.
2. **Be Clear and Concise**: Provide a detailed description of the problem or feature.
3. **Include Steps to Reproduce**: For bugs, describe how to reproduce the issue.
4. **Provide Environment Details**: Include your operating system, Go version, and any other relevant details.

Example Issue Title:
```
Bug: Server crashes when handling large files
```

Example Issue Description:
```
The server crashes when serving files larger than 100MB. Steps to reproduce:
1. Place a large file (e.g., 150MB) in the root directory.
2. Access the file via the browser.
Expected: File is served without errors.
Actual: Server crashes with a panic.
```

### **Submitting Pull Requests**

We encourage contributions via pull requests (PRs). Follow these steps:

1. **Fork the Repository**: Fork the repository to your GitHub account.
2. **Create a Branch**: Create a new branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make Changes**: Implement your changes following the [coding standards](#coding-standards).
4. **Test Your Changes**: Ensure your changes pass all tests (see [Testing](#testing)).
5. **Commit Your Changes**: Use clear and descriptive commit messages:
   ```bash
   git commit -m "Add feature: support for custom error pages"
   ```
6. **Push Your Changes**: Push your branch to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request**: Open a PR against the `main` branch of the original repository. Include a detailed description of your changes.

#### PR Guidelines:
- Keep PRs small and focused on a single issue or feature.
- Reference related issues using keywords like `Fixes #123` or `Closes #456`.
- Ensure your code adheres to the [coding standards](#coding-standards).

---

## **Development Setup**

To set up the project locally, follow these steps:

1. **Install Go**: Ensure you have Go installed:
   ```bash
   go version
   ```
   If not installed, download it from [golang.org](https://golang.org/dl/).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/hawk2012/GubinNET.git
   cd GubinNET
   ```

3. **Set Up Configuration Directory**:
   Create the configuration and logs directories:
   ```bash
   sudo mkdir -p /etc/gubinnet/{config,logs}
   ```

4. **Add Virtual Host Configuration**:
   Create an INI file for each virtual host in `/etc/gubinnet/config`. Example (`example.com.ini`):
   ```ini
   server_name=example.com
   listen_port=80
   root_path=/var/www/example
   index_file=index.html
   try_files=$uri /index.html
   use_ssl=false
   cert_path=
   key_path=
   redirect_to_https=true
   proxy_url=
   ```

5. **Build and Run the Server**:
   Build and run the server:
   ```bash
   go build -o gubinnet
   ./gubinnet
   ```

---

## **Coding Standards**

Adhere to the following coding standards to ensure consistency and maintainability:

1. **Formatting**: Use `gofmt` to format your code:
   ```bash
   gofmt -s -w .
   ```

2. **Naming Conventions**:
   - Use camelCase for variable and function names.
   - Use PascalCase for struct and interface names.

3. **Comments**:
   - Add comments for complex logic or non-obvious code.
   - Write clear and concise documentation for public functions and structs.

4. **Error Handling**:
   - Always handle errors explicitly.
   - Avoid ignoring errors unless absolutely necessary.

5. **Logging**:
   - Use the provided logger (`logger.Logger`) for logging messages.
   - Include relevant context (e.g., `request_id`, `path`, `method`) in log messages.

---

## **Testing**

Ensure your changes are tested before submitting a PR. GubinNET uses the following testing strategies:

1. **Unit Tests**: Write unit tests for new functionality using Go's `testing` package.
2. **Integration Tests**: Test interactions between components (e.g., HTTP handlers, middleware).
3. **Manual Testing**: Manually test your changes in a local environment.

Run tests using:
```bash
go test ./...
```

---

## **Documentation**

Documentation is critical for maintaining and growing the project. When contributing, ensure:

1. **README Updates**: Update the `README.md` if your changes affect user-facing features.
2. **Inline Comments**: Add inline comments for complex logic or non-obvious code.
3. **API Documentation**: Document public APIs and their usage.

---

## **Code of Conduct**

We adhere to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to:
- Be respectful and considerate.
- Avoid discriminatory or harassing behavior.
- Resolve conflicts constructively.

Report violations to [platform@gubin.systems](mailto:platform@gubin.systems).

---

Thank you for contributing to **GubinNET**! Together, we can make this project even better. 😊