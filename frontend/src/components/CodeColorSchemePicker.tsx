import { useEffect, useState } from "react"

import isDarkColor from "is-dark-color"
import { HexColorPicker, HexColorInput } from "react-colorful"

import { DEFAULT_CODE_COLOR_SCHEME } from "../lib/settings"

import styles from "./CodeColorSchemePicker.module.scss"
import ErrorBoundary from "./ErrorBoundary"

const COLOR_NAMES = {
    background: "Background",
    foreground: "Foreground",
    cursor: "Cursor",

    comment: "Comment",
    variable: "Variable",
    punctuation: "Punctuation",

    keyword: "Keyword",
    preprocessor: "Preprocessor",
    function: "Function",

    operator: "Operator",
    number: "Number",
    bool: "Boolean",

    string: "String",
    character: "Character",
    type: "Type name",
}

function Color({ color, name, onChange }) {
    const [isEditing, setIsEditing] = useState(false)
    const [isDark, setIsDark] = useState(false)

    useEffect(() => {
        try {
            setIsDark(isDarkColor(color))
        } catch (error) {
            // Ignore
        }
    }, [color])

    return <li
        aria-label={name}
        className={styles.color}
        tabIndex={0}
        onFocus={() => setIsEditing(true)}
        onClick={() => setIsEditing(true)}
        onBlur={() => setIsEditing(false)}
        data-active={isEditing}
        style={{
            color: isDark ? "white" : "black",
            backgroundColor: color,
        }}
    >
        {!isEditing && <label>{name}</label>}
        {isEditing && <>
            <HexColorPicker color={color} onChange={onChange} />
            <HexColorInput
                autoFocus={true}
                onFocus={evt => evt.target.select()}
                color={color}
                onChange={onChange}
                prefixed
            />
        </>}
    </li>
}

export type ColorScheme = Record<keyof typeof COLOR_NAMES, string>

export interface Props {
    scheme: ColorScheme
    onChange: (scheme: ColorScheme) => void
}

export default function CodeColorSchemePicker({ scheme, onChange }: Props) {
    const els = []
    for (const [key, name] of Object.entries(COLOR_NAMES)) {
        els.push(<Color
            key={key}
            color={scheme[key]}
            name={name}
            onChange={color => onChange({ ...scheme, [key]: color })}
        />)
    }

    return <ErrorBoundary onError={() => onChange(DEFAULT_CODE_COLOR_SCHEME)}>
        <ul className={styles.container}>
            {els}
        </ul>
    </ErrorBoundary>
}
