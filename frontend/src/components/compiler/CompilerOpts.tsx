import { createContext, useContext } from "react"

import useTranslation from "next-translate/useTranslation"

import * as api from "../../lib/api"
import PlatformIcon from "../PlatformSelect/PlatformIcon"
import Select from "../Select"

import CompilerFlags, { NO_TRANSLATION } from "./CompilerFlags"
import styles from "./CompilerOpts.module.css"
import { useCompilersForPlatform } from "./compilers"
import PresetSelect from "./PresetSelect"

interface IOptsContext {
    checkFlag(flag: string): boolean
    setFlag(flag: string, value: boolean): void
}

const OptsContext = createContext<IOptsContext>(undefined)

export function Checkbox({ flag, description }) {
    const { checkFlag, setFlag } = useContext(OptsContext)

    const isChecked = checkFlag(flag)

    return <div className={styles.flag} onClick={() => setFlag(flag, !isChecked)}>
        <input type="checkbox" checked={isChecked} onChange={() => setFlag(flag, !isChecked)} />
        <label>{flag}</label>
        <span className={styles.flagDescription}>{description}</span>
    </div>
}

export function FlagSet({ name, children }) {
    const { setFlag } = useContext(OptsContext)

    return <div className={styles.flagSet}>
        <div className={styles.flagSetName}>{name}</div>
        <Select
            onChange={event => {
                for (const child of children) {
                    setFlag(child.props.flag, false)
                }

                setFlag((event.target as HTMLSelectElement).value, true)
            }}
        >
            {children}
        </Select>
    </div>
}

export function FlagOption({ flag, description }: { flag: string, description?: string }) {
    const { checkFlag } = useContext(OptsContext)

    return <option
        value={flag}
        selected={checkFlag(flag)}
    >
        {flag} {description && description !== NO_TRANSLATION && `(${description})`}
    </option>
}

export type CompilerOptsT = {
    compiler: string
    compiler_flags: string
    objdump_flags: string
    preset: string
}

export type Props = {
    platform?: string
    value: CompilerOptsT
    onChange: (value: CompilerOptsT) => void
    isPopup?: boolean
}

export default function CompilerOpts({ platform, value, onChange, isPopup }: Props) {
    const compiler = value.compiler
    let opts = value.compiler_flags
    let objdump_opts = value.objdump_flags

    const setCompiler = (compiler: string) => {
        onChange({
            compiler,
            compiler_flags: opts,
            objdump_flags: objdump_opts,
            preset: "",
        })
    }

    const setOpts = (opts: string) => {
        onChange({
            compiler,
            compiler_flags: opts,
            objdump_flags: objdump_opts,
            preset: "",
        })
    }

    const setObjdumpOpts = (objdump_opts: string) => {
        onChange({
            compiler,
            compiler_flags: opts,
            objdump_flags: objdump_opts,
            preset: "",
        })
    }

    const setPreset = (preset: api.CompilerPreset) => {
        onChange({
            compiler: preset.compiler,
            compiler_flags: preset.flags,
            objdump_flags: preset.objdump_flags,
            preset: preset.name,
        })
    }

    return <div>
        <OptsContext.Provider value={{
            checkFlag(flag: string) {
                return (" " + opts + " ").includes(" " + flag + " ")
            },

            setFlag(flag: string, enable: boolean) {
                if (enable) {
                    opts = opts + " " + flag
                } else {
                    opts = (" " + opts + " ").replace(" " + flag + " ", " ")
                }
                opts = opts.trim()
                setOpts(opts)
            },
        }}>
            <div className={styles.header} data-is-popup={isPopup}>
                <PlatformIcon platform={platform} size={32} />
                <div className={styles.preset}>
                    Preset
                    <PresetSelect platform={platform} presetName={value.preset} setPreset={setPreset} />
                </div>
            </div>
            <div className={styles.container} data-is-popup={isPopup}>
                <OptsEditor platform={platform} compiler={compiler} setCompiler={setCompiler} opts={opts} setOpts={setOpts} />
            </div>
        </OptsContext.Provider>
        <OptsContext.Provider value={{
            checkFlag(flag: string) {
                return (" " + objdump_opts + " ").includes(" " + flag + " ")
            },

            setFlag(flag: string, enable: boolean) {
                if (enable) {
                    objdump_opts = objdump_opts + " " + flag
                } else {
                    objdump_opts = (" " + objdump_opts + " ").replace(" " + flag + " ", " ")
                }
                objdump_opts = objdump_opts.trim()
                setObjdumpOpts(objdump_opts)
            },
        }}>
            <div className={styles.container} data-is-popup={isPopup}>
                <ObjdumpOptsEditor platform={platform} compiler={compiler} objdump_opts={objdump_opts} setObjdumpOpts={setObjdumpOpts} />
            </div>
        </OptsContext.Provider>
    </div>
}

export function OptsEditor({ platform, compiler: compilerId, setCompiler, opts, setOpts }: {
    platform?: string
    compiler: string
    setCompiler: (compiler: string) => void
    opts: string
    setOpts: (opts: string) => void
}) {
    const compilersTranslation = useTranslation("compilers")

    const compilers = useCompilersForPlatform(platform)
    const compiler = compilers[compilerId]

    if (!compiler) {
        // TODO: this is a bug -- we should just render like an empty state
        console.warn("compiler not supported for platform", compilerId, platform)
        setCompiler(Object.keys(compilers)[0]) // pick first compiler (ew)
    }

    return <div>
        <div className={styles.row}>
            <Select
                className={styles.compilerSelect}
                onChange={e => setCompiler((e.target as HTMLSelectElement).value)}
            >
                {Object.keys(compilers).map(id => <option
                    key={id}
                    value={id}
                    selected={id === compilerId}
                >
                    {compilersTranslation.t(id)}
                </option>)}
            </Select>

            <input
                type="text"
                className={styles.textbox}
                value={opts}
                placeholder="no arguments"
                onChange={e => setOpts((e.target as HTMLInputElement).value)}
            />
        </div>

        <div className={styles.flags}>
            {(compilerId && compiler) ? <CompilerFlags schema={compiler.flags} /> : <div />}
        </div>
    </div>
}

export function ObjdumpOptsEditor({ platform, compiler: compilerId, objdump_opts, setObjdumpOpts }: {
    platform?: string
    compiler: string
    objdump_opts: string
    setObjdumpOpts: (objdump_opts: string) => void
}) {
    const compilers = useCompilersForPlatform(platform)
    const compiler = compilers[compilerId]

    return <div>
        <div className={styles.row}>
            <div className={styles.preset}>
                objdump flags
            </div>
            <input
                type="text"
                className={styles.textbox}
                value={objdump_opts}
                placeholder="no arguments"
                onChange={e => setObjdumpOpts((e.target as HTMLInputElement).value)}
            />
        </div>
        <div className={styles.objdumpFlags}>
            {(compilerId && compiler) ? <CompilerFlags schema={compiler.objdump_flags} /> : <div />}
        </div>
    </div>
}
