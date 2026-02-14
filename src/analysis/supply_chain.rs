//! Supply chain analysis: lockfile presence, version pinning, typosquat detection.

use crate::ir::dependency_surface::{DependencyIssue, DependencyIssueType, DependencySurface};

/// Well-known Python package names for typosquat comparison.
const POPULAR_PYTHON_PACKAGES: &[&str] = &[
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "boto3",
    "fastapi",
    "uvicorn",
    "httpx",
    "aiohttp",
    "pillow",
    "pydantic",
    "sqlalchemy",
    "celery",
    "redis",
    "psycopg2",
    "pytest",
    "setuptools",
    "cryptography",
    "paramiko",
    "pyyaml",
    "jinja2",
    "beautifulsoup4",
    "selenium",
    "scrapy",
    "tensorflow",
    "pytorch",
    "transformers",
    "langchain",
    "openai",
    "anthropic",
];

/// Well-known npm package names for typosquat comparison.
const POPULAR_NPM_PACKAGES: &[&str] = &[
    "express",
    "react",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "next",
    "typescript",
    "webpack",
    "eslint",
    "prettier",
    "jest",
    "mongoose",
    "sequelize",
    "prisma",
    "fastify",
    "socket.io",
    "dotenv",
    "cors",
    "jsonwebtoken",
    "bcrypt",
    "nodemailer",
    "openai",
    "langchain",
    "zod",
    "drizzle-orm",
];

/// Check dependencies for typosquat candidates.
///
/// Returns issues for any dependency whose name is within Levenshtein
/// distance 1-2 of a known popular package but is not an exact match.
pub fn check_typosquats(deps: &DependencySurface) -> Vec<DependencyIssue> {
    let mut issues = Vec::new();

    let all_popular: Vec<&str> = POPULAR_PYTHON_PACKAGES
        .iter()
        .chain(POPULAR_NPM_PACKAGES.iter())
        .copied()
        .collect();

    for dep in &deps.dependencies {
        let name = dep.name.to_lowercase();
        for &popular in &all_popular {
            if name == popular {
                continue;
            }
            let distance = levenshtein::levenshtein(&name, popular);
            if distance > 0 && distance <= 2 {
                issues.push(DependencyIssue {
                    issue_type: DependencyIssueType::PossibleTyposquat,
                    package_name: dep.name.clone(),
                    description: format!(
                        "Package '{}' is similar to popular package '{}' (edit distance {})",
                        dep.name, popular, distance
                    ),
                });
            }
        }
    }

    issues
}
