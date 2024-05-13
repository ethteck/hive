/* eslint css-modules/no-unused-class: off */

import { createContext, CSSProperties, forwardRef, HTMLAttributes, Fragment, useContext, useRef, useState } from "react"

import { VersionsIcon } from "@primer/octicons-react"
import classNames from "classnames"
import AutoSizer from "react-virtualized-auto-sizer"
import { FixedSizeList } from "react-window"

import * as api from "@/lib/api"
import { useSize } from "@/lib/hooks"
import { ThreeWayDiffBase, useCodeFontSize } from "@/lib/settings"

import Loading from "../loading.svg"

import styles from "./Diff.module.scss"
import DragBar from "./DragBar"

const PADDING_TOP = 8
const PADDING_BOTTOM = 8

// Regex for tokenizing lines for click-to-highlight purposes.
// Strings matched by the first regex group (spaces, punctuation)
// are treated as non-highlightable.
const RE_TOKEN = /([ \t,()[\]:]+|~>)|%(?:lo|hi)\([^)]+\)|[^ \t,()[\]:]+/g

const SelectedSourceLineContext = createContext<number | null>(null)

type Highlighter = {
    value: string | null
    setValue: (value: string | null) => void
    select: (value: string) => void
}

function useHighlighter(setAll: Highlighter["setValue"]): Highlighter {
    const [value, setValue] = useState(null)
    return {
        value,
        setValue,
        select: newValue => {
            // When selecting the same value twice (double-clicking), select it
            // in all diff columns
            if (value === newValue) {
                setAll(newValue)
            } else {
                setValue(newValue)
            }
        },
    }
}

function FormatDiffText({ texts, highlighter }: {
    texts: api.DiffText[]
    highlighter: Highlighter
}) {
    return <> {
        texts.map((t, index1) =>
            Array.from(t.text.matchAll(RE_TOKEN)).map((match, index2) => {
                const text = match[0]
                const isToken = !match[1]
                const key = index1 + "," + index2

                let className: string
                if (t.format == "rotation") {
                    className = styles[`rotation${t.index % 9}`]
                } else if (t.format) {
                    className = styles[t.format]
                }

                return <span
                    key={key}
                    className={classNames(className, {
                        [styles.highlightable]: isToken,
                        [styles.highlighted]: (highlighter.value === text),
                    })}
                    onClick={e => {
                        if (isToken) {
                            highlighter.select(text)
                            e.stopPropagation()
                        }
                    }}
                >
                    {text}
                </span>
            })
        )
    }</>
}

function scrollToSourceFromLineNumber(cell: api.DiffCell | undefined) {
    if (cell) {
        // item(0) is the source tab
        // item(1) is the context tab
        const lineNumbersEle = document.getElementsByClassName("cm-gutter cm-lineNumbers").item(0)
        const scrollerEle = document.getElementsByClassName("cm-scroller").item(0)
        if (lineNumbersEle) {
            const lineNumberEle = lineNumbersEle.children[cell.src_line]
            if (lineNumberEle) {
                scrollerEle.scroll({
                    left: lineNumberEle.offsetLeft,
                    top: lineNumberEle.offsetTop,
                    behavior: "smooth" // smoothly scroll to the line
                })
            }
        }
    }
}

function DiffCell({ cell, className, highlighter }: {
    cell: api.DiffCell | undefined
    className?: string
    highlighter: Highlighter
}) {
    const selectedSourceLine = useContext(SelectedSourceLineContext)
    const hasLineNo = typeof cell?.src_line != "undefined"

    if (!cell)
        return <div className={classNames(styles.cell, className)} />

    return <div
        className={classNames(styles.cell, className, {
            [styles.highlight]: hasLineNo && cell.src_line == selectedSourceLine,
        })}
    >
        {hasLineNo && <span className={styles.lineNumber}><button onClick={() => scrollToSourceFromLineNumber(cell)}>{cell.src_line}</button></span>}
        <FormatDiffText texts={cell.text} highlighter={highlighter} />
    </div>
}

function DiffRow({ row, style, highlighter1, highlighter2, highlighter3 }: {
    row: api.DiffRow
    style: CSSProperties
    highlighter1: Highlighter
    highlighter2: Highlighter
    highlighter3: Highlighter
}) {
    return <li
        className={styles.row}
        style={{
            ...style,
            top: `${parseFloat(style.top.toString()) + PADDING_TOP}px`,
            lineHeight: `${style.height.toString()}px`,
        }}
    >
        <DiffCell cell={row.base} highlighter={highlighter1} />
        <DiffCell cell={row.current} highlighter={highlighter2} />
        <DiffCell cell={row.previous} highlighter={highlighter3} />
    </li>
}

// https://github.com/bvaughn/react-window#can-i-add-padding-to-the-top-and-bottom-of-a-list
const innerElementType = forwardRef<HTMLUListElement, HTMLAttributes<HTMLUListElement>>(({ style, ...rest }, ref) => {
    return <ul
        ref={ref}
        style={{
            ...style,
            height: `${parseFloat(style.height.toString()) + PADDING_TOP + PADDING_BOTTOM}px`,
        }}
        {...rest}
    />
})
innerElementType.displayName = "innerElementType"

function DiffBody({ diff, fontSize }: { diff: api.DiffOutput | null, fontSize: number | undefined }) {
    const setHighlightAll: Highlighter["setValue"] = value => {
        highlighter1.setValue(value)
        highlighter2.setValue(value)
        highlighter3.setValue(value)
    }
    const highlighter1 = useHighlighter(setHighlightAll)
    const highlighter2 = useHighlighter(setHighlightAll)
    const highlighter3 = useHighlighter(setHighlightAll)

    return <div
        className={styles.bodyContainer}
        onClick={() => {
            // If clicks propagate to the container, clear all
            setHighlightAll(null)
        }}
    >
        {diff?.rows && <AutoSizer>
            {({ height, width }: {height: number|undefined, width:number|undefined}) => (
                <FixedSizeList
                    className={styles.body}
                    itemCount={diff.rows.length}
                    itemData={diff.rows}
                    itemSize={(fontSize ?? 12) * 1.33}
                    overscanCount={40}
                    width={width}
                    height={height}
                    innerElementType={innerElementType}
                >
                    {({ data, index, style }) =>
                        <DiffRow
                            row={data[index]}
                            style={style}
                            highlighter1={highlighter1}
                            highlighter2={highlighter2}
                            highlighter3={highlighter3}
                        />
                    }
                </FixedSizeList>
            )}
        </AutoSizer>}
    </div>
}

function ThreeWayToggleButton({ enabled, setEnabled }: { enabled: boolean, setEnabled: (enabled: boolean) => void }) {
    return <button
        className={styles.threeWayToggle}
        onClick={() => {
            setEnabled(!enabled)
        }}
        title={enabled ? "Disable three-way diffing" : "Enable three-way diffing"}
    >
        <VersionsIcon size={24} />
        <div className={styles.threeWayToggleNumber}>
            {enabled ? "3" : "2"}
        </div>
    </button>
}

export type Props = {
    diff: api.DiffOutput | null
    isCompiling: boolean
    isCurrentOutdated: boolean
    threeWayDiffEnabled: boolean
    setThreeWayDiffEnabled: (value: boolean) => void
    threeWayDiffBase: ThreeWayDiffBase
    selectedSourceLine: number | null
}

export default function Diff({ diff, isCompiling, isCurrentOutdated, threeWayDiffEnabled, setThreeWayDiffEnabled, threeWayDiffBase, selectedSourceLine }: Props) {
    const [fontSize] = useCodeFontSize()

    const container = useSize<HTMLDivElement>()

    const [bar1Pos, setBar1Pos] = useState(NaN)
    const [bar2Pos, setBar2Pos] = useState(NaN)

    const columnMinWidth = 100
    const clampedBar1Pos = Math.max(columnMinWidth, Math.min(container.width - columnMinWidth - (threeWayDiffEnabled ? columnMinWidth : 0), bar1Pos))
    const clampedBar2Pos = threeWayDiffEnabled ? Math.max(clampedBar1Pos + columnMinWidth, Math.min(container.width - columnMinWidth, bar2Pos)) : container.width

    // Distribute the bar positions across the container when its width changes
    const updateBarPositions = (threeWayDiffEnabled: boolean) => {
        const numSections = threeWayDiffEnabled ? 3 : 2
        setBar1Pos(container.width / numSections)
        setBar2Pos(container.width / numSections * 2)
    }
    const lastContainerWidthRef = useRef(NaN)
    if (lastContainerWidthRef.current !== container.width && container.width) {
        lastContainerWidthRef.current = container.width
        updateBarPositions(threeWayDiffEnabled)
    }

    const threeWayButton = <>
        <div className={styles.spacer} />
        <ThreeWayToggleButton
            enabled={threeWayDiffEnabled}
            setEnabled={(enabled: boolean) => {
                updateBarPositions(enabled)
                setThreeWayDiffEnabled(enabled)
            }}
        />
    </>

    return <div
        ref={container.ref}
        className={styles.diff}
        style={{
            "--diff-font-size": typeof fontSize == "number" ? `${fontSize}px` : "",
            "--diff-left-width": `${clampedBar1Pos}px`,
            "--diff-right-width": `${container.width - clampedBar2Pos}px`,
            "--diff-current-filter": isCurrentOutdated ? "grayscale(25%) brightness(70%)" : "",
        } as CSSProperties}
    >
        <DragBar pos={clampedBar1Pos} onChange={setBar1Pos} />
        {threeWayDiffEnabled && <DragBar pos={clampedBar2Pos} onChange={setBar2Pos} />}
        <div className={styles.headers}>
            <div className={styles.header}>
                Target
            </div>
            <div className={styles.header}>
                Current
                {isCompiling && <Loading width={20} height={20} />}
                {!threeWayDiffEnabled && threeWayButton}
            </div>
            {threeWayDiffEnabled && <div className={styles.header}>
                {threeWayDiffBase === ThreeWayDiffBase.SAVED ? "Saved" : "Previous"}
                {threeWayButton}
            </div>}
        </div>
        <SelectedSourceLineContext.Provider value={selectedSourceLine}>
            <DiffBody diff={diff} fontSize={fontSize} />
        </SelectedSourceLineContext.Provider>
    </div>
}
