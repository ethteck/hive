import { createContext, ReactNode, useContext } from "react"

import Link from "next/link"

import styles from "./VerticalMenu.module.scss"

const MenuContext = createContext({ close: () => {} })

export default function VerticalMenu({ children, close }: { children: ReactNode, close: () => void }) {
    return <MenuContext.Provider value={{ close }}>
        <ul
            className={styles.menu}
            onClick={evt => {
                // Prevent reopening the menu
                evt.stopPropagation()
            }}
        >
            {children}
        </ul>
    </MenuContext.Provider>
}

export function MenuItem({ children }: { children: ReactNode }) {
    return <li className={styles.item}>
        {children}
    </li>
}

export function ButtonItem({ children, onClick }: { children: ReactNode, onClick: () => void }) {
    const { close } = useContext(MenuContext)

    return <a
        className={styles.item}
        onClick={() => {
            onClick()
            close()
        }}
    >
        {children}
    </a>
}

export function LinkItem({ children, href }: { children: ReactNode, href: string }) {
    const { close } = useContext(MenuContext)

    return <Link href={href}>
        <a
            className={styles.item}
            onClick={_evt => {
                close()
            }}
        >
            {children}
        </a>
    </Link>
}
